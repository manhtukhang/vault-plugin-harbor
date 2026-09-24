package harbor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

const (
	harborAPIPath        = "/api/v2.0"
	maxResponseBodyBytes = 16 << 20
	maxErrorMessageBytes = 512
	robotListPageSize    = 100
	robotListMaxPages    = 50
	httpClientTimeout    = 60 * time.Second

	retryAttempts    = 3
	retryBaseBackoff = 250 * time.Millisecond
	// A Vault expiration worker must not block on a server-controlled delay, so a Retry-After
	// beyond this cap gives up immediately instead of waiting it out.
	retryAfterMax = 5 * time.Second
)

// harborClient calls the Harbor v2.0 API directly: goharbor-client's go-openapi runtime dumps credentials on DEBUG, reads unbounded bodies and returns unsanitized errors.
type harborClient struct {
	url      string
	username string
	password string
	http     *http.Client
}

// harborAPIError is returned when Harbor answers with a non-2xx status.
type harborAPIError struct {
	StatusCode int
	Message    string
	RetryAfter time.Duration
}

func (e *harborAPIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("harbor API returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("harbor API returned HTTP %d: %s", e.StatusCode, e.Message)
}

func isNotFound(err error) bool {
	var apiErr *harborAPIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// newClient creates a new client to access harbor
// and exposes it for any secrets or roles to use.
func newClient(config *harborConfig) (*harborClient, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	if config.Username == "" {
		return nil, errors.New("client username was not defined")
	}

	if config.Password == "" {
		return nil, errors.New("client password was not defined")
	}

	if config.URL == "" {
		return nil, errors.New("client URL was not defined")
	}

	httpClient, err := newHTTPClient(config.CACert)
	if err != nil {
		return nil, err
	}

	return &harborClient{
		url:      config.URL,
		username: config.Username,
		password: config.Password,
		http:     httpClient,
	}, nil
}

func newHTTPClient(caCert string) (*http.Client, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}
	if caCert != "" {
		certs, err := parseCACerts(caCert)
		if err != nil {
			return nil, err
		}
		for _, cert := range certs {
			rootCAs.AddCert(cert)
		}
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    rootCAs,
			},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          10,
			ForceAttemptHTTP2:     true,
		},
		Timeout: httpClientTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// parseCACerts decodes every certificate of a PEM bundle. x509.CertPool.AppendCertsFromPEM reports
// success as soon as one block parses and silently drops the rest, so a chain with a corrupt
// intermediate would be accepted here and only surface later as an opaque TLS handshake failure.
func parseCACerts(caCert string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var badType string

	rest := bytes.TrimSpace([]byte(caCert))
	for len(rest) > 0 {
		// pem.Decode skips whatever precedes the next block, so the block must start here.
		if !bytes.HasPrefix(rest, []byte("-----BEGIN")) {
			return nil, errors.New("ca_cert contains data that is not PEM encoded")
		}
		block, remainder := pem.Decode(rest)
		if block == nil {
			return nil, errors.New("ca_cert contains a PEM block that cannot be decoded")
		}
		if block.Type != "CERTIFICATE" {
			badType = block.Type
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ca_cert certificate %d cannot be parsed: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
		rest = bytes.TrimSpace(remainder)
	}

	// A bundle holding no certificate at all is reported as such, rather than by its first odd block.
	if len(certs) == 0 {
		return nil, errors.New("ca_cert does not contain a valid PEM certificate")
	}
	if badType != "" {
		return nil, fmt.Errorf("ca_cert contains a %q PEM block, expected CERTIFICATE", badType)
	}
	return certs, nil
}

// validateCACert reports whether a PEM bundle is usable; parseCACerts returns the certificates
// themselves when the caller needs to report how many were loaded.
func validateCACert(caCert string) error {
	_, err := parseCACerts(caCert)
	return err
}

func (c *harborClient) newRequest(ctx context.Context, method, path string, query url.Values, body interface{}) (*http.Request, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(b)
	}

	u := c.url + harborAPIPath + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// isIdempotent reports whether replaying the request is safe. Robot creation (POST) and the password
// change (PUT) stay single-shot: the write-ahead log already covers an ambiguous create, while a
// blind retry would mint a duplicate robot or race the rotation.
func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodDelete, http.MethodHead:
		return true
	default:
		return false
	}
}

// isRetryableError reports whether err is worth another attempt. net/http wraps every transport
// failure in *url.Error, so reading or decoding failures are excluded.
func isRetryableError(err error) bool {
	var apiErr *harborAPIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500
	}

	var urlErr *url.Error
	return errors.As(err, &urlErr)
}

// retryAfterDelay parses Retry-After, which Harbor sends as delta-seconds; HTTP also allows a date.
func retryAfterDelay(header http.Header) time.Duration {
	value := strings.TrimSpace(header.Get("Retry-After"))
	if value == "" {
		return 0
	}

	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		if delay := time.Until(date); delay > 0 {
			return delay
		}
	}
	return 0
}

// jitter returns a random duration in [0, d) so concurrent leases do not retry in lockstep.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d)))
	if err != nil {
		return d / 2
	}
	return time.Duration(n.Int64())
}

// waitBeforeRetry backs off exponentially, honoring Retry-After up to retryAfterMax. A non-nil
// return means the caller must give up with the error it already has.
func waitBeforeRetry(ctx context.Context, attempt int, err error) error {
	backoff := retryBaseBackoff << attempt
	wait := backoff/2 + jitter(backoff/2)

	var apiErr *harborAPIError
	if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
		if apiErr.RetryAfter > retryAfterMax {
			return fmt.Errorf("harbor asked to retry after %s, beyond the %s cap", apiErr.RetryAfter, retryAfterMax)
		}
		wait = max(wait, apiErr.RetryAfter)
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *harborClient) send(req *http.Request, out interface{}) (http.Header, error) {
	retryable := isIdempotent(req.Method)

	for attempt := 0; ; attempt++ {
		attemptReq := req
		if attempt > 0 {
			attemptReq = req.Clone(req.Context())
		}

		header, err := c.roundTrip(attemptReq, out)
		if err == nil || !retryable || attempt == retryAttempts-1 || !isRetryableError(err) {
			return header, err
		}
		if waitErr := waitBeforeRetry(req.Context(), attempt, err); waitErr != nil {
			return nil, err
		}
	}
}

func (c *harborClient) roundTrip(req *http.Request, out interface{}) (http.Header, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("error reading Harbor response: %w", err)
	}
	if len(data) > maxResponseBodyBytes {
		return nil, fmt.Errorf("harbor response exceeds %d bytes", maxResponseBodyBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &harborAPIError{
			StatusCode: resp.StatusCode,
			Message:    harborErrorMessage(data),
			RetryAfter: retryAfterDelay(resp.Header),
		}
	}

	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return nil, fmt.Errorf("error decoding Harbor response: %w", err)
		}
	}
	return resp.Header, nil
}

func (c *harborClient) do(ctx context.Context, method, path string, query url.Values, body, out interface{}) (http.Header, error) {
	req, err := c.newRequest(ctx, method, path, query, body)
	if err != nil {
		return nil, err
	}
	return c.send(req, out)
}

func harborErrorMessage(body []byte) string {
	var payload struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}

	msgs := make([]string, 0, len(payload.Errors))
	for _, e := range payload.Errors {
		if e.Message != "" {
			msgs = append(msgs, e.Message)
		}
	}
	msg := strings.Join(msgs, "; ")
	if len(msg) > maxErrorMessageBytes {
		msg = msg[:maxErrorMessageBytes]
	}
	return msg
}

// verifyConnection performs an authenticated call that only needs the robot:list permission.
func (c *harborClient) verifyConnection(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodGet, "/robots", url.Values{"page": {"1"}, "page_size": {"1"}}, nil, nil)
	return err
}

func (c *harborClient) NewRobotAccount(ctx context.Context, r *harborModel.RobotCreate) (*harborModel.RobotCreated, error) {
	var created *harborModel.RobotCreated
	if _, err := c.do(ctx, http.MethodPost, "/robots", nil, r, &created); err != nil {
		return nil, err
	}
	return created, nil
}

func (c *harborClient) GetRobotAccountByID(ctx context.Context, id int64) (*harborModel.Robot, error) {
	var robot *harborModel.Robot
	if _, err := c.do(ctx, http.MethodGet, "/robots/"+strconv.FormatInt(id, 10), nil, nil, &robot); err != nil {
		return nil, err
	}
	if robot == nil {
		return nil, fmt.Errorf("harbor returned an empty robot account %d", id)
	}
	if robot.ID != id {
		return nil, fmt.Errorf("harbor returned robot account %d instead of %d", robot.ID, id)
	}
	return robot, nil
}

func (c *harborClient) DeleteRobotAccountByID(ctx context.Context, id int64) error {
	_, err := c.do(ctx, http.MethodDelete, "/robots/"+strconv.FormatInt(id, 10), nil, nil, nil)
	return err
}

// ListRobotAccounts returns every robot account matching the Harbor query q, across all pages.
func (c *harborClient) ListRobotAccounts(ctx context.Context, q string) ([]*harborModel.Robot, error) {
	var robots []*harborModel.Robot
	seen := map[int64]struct{}{}
	for page := int64(1); page <= robotListMaxPages; page++ {
		query := url.Values{
			"page":      {strconv.FormatInt(page, 10)},
			"page_size": {strconv.Itoa(robotListPageSize)},
		}
		if q != "" {
			query.Set("q", q)
		}

		var payload []*harborModel.Robot
		header, err := c.do(ctx, http.MethodGet, "/robots", query, nil, &payload)
		if err != nil {
			return nil, err
		}

		added := 0
		for _, robot := range payload {
			if robot == nil {
				continue
			}
			if _, dup := seen[robot.ID]; dup {
				continue
			}
			seen[robot.ID] = struct{}{}
			robots = append(robots, robot)
			added++
		}

		total, err := strconv.ParseInt(header.Get("X-Total-Count"), 10, 64)
		if len(payload) < robotListPageSize || added == 0 || (err == nil && int64(len(robots)) >= total) {
			return robots, nil
		}
	}
	return nil, fmt.Errorf("harbor returned more than %d pages of robot accounts", robotListMaxPages)
}

func (c *harborClient) GetCurrentUser(ctx context.Context) (*harborModel.UserResp, error) {
	var user *harborModel.UserResp
	if _, err := c.do(ctx, http.MethodGet, "/users/current", nil, nil, &user); err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("harbor returned an empty current user")
	}
	return user, nil
}

func (c *harborClient) UpdateUserPassword(ctx context.Context, id int64, oldPassword, newPassword string) error {
	body := &harborModel.PasswordReq{OldPassword: oldPassword, NewPassword: newPassword}
	_, err := c.do(ctx, http.MethodPut, "/users/"+strconv.FormatInt(id, 10)+"/password", nil, body, nil)
	return err
}

func (c *harborClient) GetProjectID(ctx context.Context, name string) (int64, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/projects/"+url.PathEscape(name), nil, nil)
	if err != nil {
		return 0, err
	}
	// Harbor treats an all-digit project name as a project ID unless told otherwise.
	req.Header.Set("X-Is-Resource-Name", "true")

	var project *harborModel.Project
	if _, err := c.send(req, &project); err != nil {
		return 0, err
	}
	if project == nil || project.ProjectID <= 0 {
		return 0, fmt.Errorf("harbor returned an invalid project %q", name)
	}
	return int64(project.ProjectID), nil
}
