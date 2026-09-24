package harbor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
	"github.com/stretchr/testify/require"
)

func TestNormalizeURL(t *testing.T) {
	valid := map[string]string{
		"https://harbor.example.com":             "https://harbor.example.com",
		"https://Harbor.Example.com/":            "https://harbor.example.com",
		" https://harbor.example.com:8443// ":    "https://harbor.example.com:8443",
		"https://harbor.example.com/api/v2.0":    "https://harbor.example.com",
		"https://harbor.example.com/api/v2.0/":   "https://harbor.example.com",
		"https://example.com/harbor/api/v2.0///": "https://example.com/harbor",
		"https://harbor.example.com:443/":        "https://harbor.example.com",
		"https://harbor.example.com.:443":        "https://harbor.example.com.",
		"https://harbor.example.com.":            "https://harbor.example.com.",
		"https://[::1]:443/api/v2.0":             "https://[::1]",
		"https://harbor.example.com:4430":        "https://harbor.example.com:4430",
	}
	for in, expected := range valid {
		t.Run(in, func(t *testing.T) {
			got, err := normalizeURL(in)
			require.NoError(t, err)
			require.Equal(t, expected, got)
		})
	}

	invalid := map[string]string{
		"http://harbor.example.com":            "https",
		"ftp://harbor.example.com":             "https",
		"harbor.example.com":                   "https",
		"":                                     "https",
		"https://":                             "host",
		"https:opaque":                         "host",
		"https://admin:S3cret@harbor.example":  "credentials",
		"https://harbor.example.com?x=1":       "query",
		"https://harbor.example.com/?":         "query",
		"https://harbor.example.com/#frag":     "fragment",
		"https://harbor.example.com/%zz":       "parsed",
		"https://admin:S3cret@harbor%zz.local": "parsed",
	}
	for in, contains := range invalid {
		t.Run("invalid "+in, func(t *testing.T) {
			_, err := normalizeURL(in)
			require.Error(t, err)
			require.Contains(t, err.Error(), contains)
			require.NotContains(t, err.Error(), "S3cret")
		})
	}
}

func TestNewHTTPClientSettings(t *testing.T) {
	hc, err := newHTTPClient("")
	require.NoError(t, err)

	tr, ok := hc.Transport.(*http.Transport)
	require.True(t, ok)
	require.Nil(t, tr.Proxy)
	require.Equal(t, uint16(tls.VersionTLS12), tr.TLSClientConfig.MinVersion)
	require.NotZero(t, tr.TLSHandshakeTimeout)
	require.NotZero(t, tr.ResponseHeaderTimeout)
	require.NotZero(t, hc.Timeout)
	require.NotNil(t, hc.CheckRedirect)

	_, err = newHTTPClient("not a certificate")
	require.ErrorContains(t, err, "ca_cert")
}

func TestClientCACert(t *testing.T) {
	f := newFakeHarbor(t)

	c, err := newClient(&harborConfig{URL: f.URL(), Username: fakeHarborUsername, Password: fakeHarborPassword})
	require.NoError(t, err)
	err = c.verifyConnection(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "certificate")

	c, err = newClient(&harborConfig{URL: f.URL(), Username: fakeHarborUsername, Password: fakeHarborPassword, CACert: f.CACert()})
	require.NoError(t, err)
	require.NoError(t, c.verifyConnection(context.Background()))
}

func TestNewClientValidation(t *testing.T) {
	_, err := newClient(nil)
	require.Error(t, err)
	_, err = newClient(&harborConfig{Password: "p", URL: "https://h"})
	require.ErrorContains(t, err, "username")
	_, err = newClient(&harborConfig{Username: "u", URL: "https://h"})
	require.ErrorContains(t, err, "password")
	_, err = newClient(&harborConfig{Username: "u", Password: "p"})
	require.ErrorContains(t, err, "URL")
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Int32
	record := func(r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Add(1)
		}
	}

	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		writeJSON(w, http.StatusOK, map[string]interface{}{"id": 1, "name": "robot$x"})
	}))
	defer target.Close()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/moved"):
			record(r)
			writeJSON(w, http.StatusOK, map[string]interface{}{"id": 1, "name": "robot$x"})
		case strings.HasSuffix(r.URL.Path, "/1"):
			http.Redirect(w, r, "/moved", http.StatusTemporaryRedirect)
		default:
			w.Header().Set("Location", target.URL+"/api/v2.0/robots/2")
			w.WriteHeader(http.StatusFound)
		}
	}))
	defer origin.Close()

	c, err := newClient(&harborConfig{
		URL:      origin.URL,
		Username: fakeHarborUsername,
		Password: fakeHarborPassword,
		CACert:   (&fakeHarbor{server: origin}).CACert(),
	})
	require.NoError(t, err)

	for id, status := range map[int64]int{1: http.StatusTemporaryRedirect, 2: http.StatusFound} {
		_, err = c.GetRobotAccountByID(context.Background(), id)
		var apiErr *harborAPIError
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, status, apiErr.StatusCode)
	}
	require.Zero(t, leaked.Load())
}

func TestClientResponseBodyLimit(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat(" ", maxResponseBodyBytes+1)))
	}))
	defer srv.Close()

	c, err := newClient(&harborConfig{URL: srv.URL, Username: "u", Password: "p", CACert: (&fakeHarbor{server: srv}).CACert()})
	require.NoError(t, err)

	_, err = c.GetRobotAccountByID(context.Background(), 1)
	require.ErrorContains(t, err, "exceeds")
}

func TestClientErrors(t *testing.T) {
	f := newFakeHarbor(t)
	c, err := newClient(&harborConfig{URL: f.URL(), Username: fakeHarborUsername, Password: "wrong", CACert: f.CACert()})
	require.NoError(t, err)

	err = c.verifyConnection(context.Background())
	var apiErr *harborAPIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
	require.Equal(t, "harbor API returned HTTP 401: unauthorized", err.Error())
	require.False(t, isNotFound(err))

	require.Equal(t, "harbor API returned HTTP 500", (&harborAPIError{StatusCode: 500}).Error())

	require.Equal(t, "a; b", harborErrorMessage([]byte(`{"errors":[{"message":"a"},{"message":""},{"message":"b"}]}`)))
	require.Empty(t, harborErrorMessage([]byte("<html>proxy error</html>")))
	require.Len(t, harborErrorMessage([]byte(`{"errors":[{"message":"`+strings.Repeat("x", 2000)+`"}]}`)), maxErrorMessageBytes)
}

func TestClientListRobotAccountsPagination(t *testing.T) {
	for _, count := range []int{0, 99, 100, 200, 250} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := newFakeHarbor(t)
			for i := 0; i < count; i++ {
				f.addRobot(fmt.Sprintf("r%d", i), robotKindSystem, 0, "")
			}
			c, err := newClient(&harborConfig{URL: f.URL(), Username: fakeHarborUsername, Password: fakeHarborPassword, CACert: f.CACert()})
			require.NoError(t, err)

			robots, err := c.ListRobotAccounts(context.Background(), "")
			require.NoError(t, err)
			require.Len(t, robots, count)
			require.Len(t, f.requestLog(), count/robotListPageSize+1-boolToInt(count > 0 && count%robotListPageSize == 0))
			for _, req := range f.requestLog() {
				require.Contains(t, req, "page_size=100")
				require.NotContains(t, req, "page=0")
			}
		})
	}
}

func TestClientListRobotAccountsBrokenPagination(t *testing.T) {
	newListClient := func(t *testing.T, handler func(page int) []map[string]interface{}) (*harborClient, *atomic.Int32) {
		t.Helper()
		var calls atomic.Int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			writeJSON(w, http.StatusOK, handler(page))
		}))
		t.Cleanup(srv.Close)
		c, err := newClient(&harborConfig{URL: srv.URL, Username: "u", Password: "p", CACert: (&fakeHarbor{server: srv}).CACert()})
		require.NoError(t, err)
		return c, &calls
	}
	fullPage := func(firstID int) []map[string]interface{} {
		robots := make([]map[string]interface{}, robotListPageSize)
		for i := range robots {
			robots[i] = map[string]interface{}{"id": firstID + i, "name": fmt.Sprintf("robot$r%d", firstID+i)}
		}
		return robots
	}

	t.Run("page ignored without total", func(t *testing.T) {
		c, calls := newListClient(t, func(int) []map[string]interface{} { return fullPage(1) })
		robots, err := c.ListRobotAccounts(context.Background(), "")
		require.NoError(t, err)
		require.Len(t, robots, robotListPageSize)
		require.EqualValues(t, 2, calls.Load())
	})

	t.Run("endless pages", func(t *testing.T) {
		c, calls := newListClient(t, func(page int) []map[string]interface{} { return fullPage(page * 1000) })
		_, err := c.ListRobotAccounts(context.Background(), "")
		require.ErrorContains(t, err, "more than 50 pages")
		require.EqualValues(t, robotListMaxPages, calls.Load())
	})
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestClientGetProjectID(t *testing.T) {
	f := newFakeHarbor(t)
	f.projects["123"] = 7
	c, err := newClient(&harborConfig{URL: f.URL(), Username: fakeHarborUsername, Password: fakeHarborPassword, CACert: f.CACert()})
	require.NoError(t, err)

	id, err := c.GetProjectID(context.Background(), "123")
	require.NoError(t, err)
	require.Equal(t, int64(7), id)

	_, err = c.GetProjectID(context.Background(), "missing")
	require.True(t, isNotFound(err))
}

func newFakeHarborClient(t *testing.T, f *fakeHarbor) *harborClient {
	t.Helper()
	c, err := newClient(&harborConfig{URL: f.URL(), Username: fakeHarborUsername, Password: fakeHarborPassword, CACert: f.CACert()})
	require.NoError(t, err)
	return c
}

// failFirst answers the first n requests with status, then lets the fake Harbor handle the rest.
func failFirst(f *fakeHarbor, n int32, status int, retryAfter string) *atomic.Int32 {
	var calls atomic.Int32
	f.onRequest = func(w http.ResponseWriter, _ *http.Request) bool {
		if calls.Add(1) > n {
			return false
		}
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		writeHarborError(w, status, "try again")
		return true
	}
	return &calls
}

func TestClientRetriesIdempotentRequests(t *testing.T) {
	t.Run("get succeeds after 5xx", func(t *testing.T) {
		f := newFakeHarbor(t)
		id := f.addRobot("r", robotKindSystem, 0, "")
		calls := failFirst(f, 2, http.StatusServiceUnavailable, "")

		robot, err := newFakeHarborClient(t, f).GetRobotAccountByID(context.Background(), id)
		require.NoError(t, err)
		require.Equal(t, id, robot.ID)
		require.EqualValues(t, retryAttempts, calls.Load())
	})

	t.Run("delete succeeds after 429", func(t *testing.T) {
		f := newFakeHarbor(t)
		id := f.addRobot("r", robotKindSystem, 0, "")
		calls := failFirst(f, 1, http.StatusTooManyRequests, "")

		require.NoError(t, newFakeHarborClient(t, f).DeleteRobotAccountByID(context.Background(), id))
		require.Equal(t, []int64{id}, f.deletedIDs())
		require.EqualValues(t, 2, calls.Load())
	})

	t.Run("gives up after retryAttempts", func(t *testing.T) {
		f := newFakeHarbor(t)
		calls := failFirst(f, 10, http.StatusBadGateway, "")

		_, err := newFakeHarborClient(t, f).GetRobotAccountByID(context.Background(), 1)
		var apiErr *harborAPIError
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, http.StatusBadGateway, apiErr.StatusCode)
		require.EqualValues(t, retryAttempts, calls.Load())
	})

	t.Run("4xx is not retried", func(t *testing.T) {
		f := newFakeHarbor(t)

		_, err := newFakeHarborClient(t, f).GetRobotAccountByID(context.Background(), 404)
		require.True(t, isNotFound(err))
		require.Len(t, f.requestLog(), 1)
	})

	t.Run("transport error is retried", func(t *testing.T) {
		var calls atomic.Int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				conn, _, _ := w.(http.Hijacker).Hijack()
				if conn != nil {
					_ = conn.Close()
				}
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"id": 1, "name": "robot$x"})
		}))
		defer srv.Close()

		c, err := newClient(&harborConfig{URL: srv.URL, Username: "u", Password: "p", CACert: (&fakeHarbor{server: srv}).CACert()})
		require.NoError(t, err)

		robot, err := c.GetRobotAccountByID(context.Background(), 1)
		require.NoError(t, err)
		require.EqualValues(t, 1, robot.ID)
		require.EqualValues(t, 2, calls.Load())
	})
}

func TestClientDoesNotRetryWrites(t *testing.T) {
	create := &harborModel.RobotCreate{
		Name:        "r",
		Level:       robotKindSystem,
		Duration:    1,
		Permissions: []*harborModel.RobotPermission{{Kind: robotKindSystem, Namespace: "/"}},
	}

	t.Run("post is single-shot", func(t *testing.T) {
		f := newFakeHarbor(t)
		calls := failFirst(f, 10, http.StatusServiceUnavailable, "")

		_, err := newFakeHarborClient(t, f).NewRobotAccount(context.Background(), create)
		require.Error(t, err)
		require.EqualValues(t, 1, calls.Load())
	})

	t.Run("put is single-shot", func(t *testing.T) {
		f := newFakeHarbor(t)
		calls := failFirst(f, 10, http.StatusServiceUnavailable, "")

		require.Error(t, newFakeHarborClient(t, f).UpdateUserPassword(context.Background(), 1, "old", "new"))
		require.EqualValues(t, 1, calls.Load())
	})

	// The same failure on a read proves the gate is the method, not the response.
	t.Run("get under the same failure is retried", func(t *testing.T) {
		f := newFakeHarbor(t)
		calls := failFirst(f, 10, http.StatusServiceUnavailable, "")

		require.Error(t, newFakeHarborClient(t, f).verifyConnection(context.Background()))
		require.EqualValues(t, retryAttempts, calls.Load())
	})
}

func TestClientRetryAfter(t *testing.T) {
	t.Run("honored under the cap", func(t *testing.T) {
		f := newFakeHarbor(t)
		id := f.addRobot("r", robotKindSystem, 0, "")
		calls := failFirst(f, 1, http.StatusTooManyRequests, "1")

		start := time.Now()
		robot, err := newFakeHarborClient(t, f).GetRobotAccountByID(context.Background(), id)
		require.NoError(t, err)
		require.Equal(t, id, robot.ID)
		require.EqualValues(t, 2, calls.Load())
		require.GreaterOrEqual(t, time.Since(start), time.Second)
	})

	t.Run("beyond the cap fails fast", func(t *testing.T) {
		f := newFakeHarbor(t)
		calls := failFirst(f, 10, http.StatusTooManyRequests, strconv.Itoa(int(retryAfterMax/time.Second)+1))

		start := time.Now()
		_, err := newFakeHarborClient(t, f).GetRobotAccountByID(context.Background(), 1)
		var apiErr *harborAPIError
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, http.StatusTooManyRequests, apiErr.StatusCode)
		require.EqualValues(t, 1, calls.Load())
		require.Less(t, time.Since(start), time.Second)
	})
}

func TestClientRetryRespectsContext(t *testing.T) {
	f := newFakeHarbor(t)
	calls := failFirst(f, 10, http.StatusTooManyRequests, strconv.Itoa(int(retryAfterMax/time.Second)))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := newFakeHarborClient(t, f).GetRobotAccountByID(ctx, 1)
	require.Error(t, err)
	require.EqualValues(t, 1, calls.Load())
	require.Less(t, time.Since(start), time.Second)
}

func TestRetryAfterDelay(t *testing.T) {
	for value, expected := range map[string]time.Duration{
		"":            0,
		"1":           time.Second,
		"0":           0,
		"-5":          0,
		"not-a-delay": 0,
	} {
		t.Run("value "+value, func(t *testing.T) {
			require.Equal(t, expected, retryAfterDelay(http.Header{"Retry-After": {value}}))
		})
	}

	require.Greater(t, retryAfterDelay(http.Header{"Retry-After": {time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)}}), 20*time.Second)
	require.Zero(t, retryAfterDelay(http.Header{"Retry-After": {time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat)}}))
}

func TestClientGetRobotAccountIDMismatch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"id": 99, "name": "robot$other"})
	}))
	defer srv.Close()

	c, err := newClient(&harborConfig{URL: srv.URL, Username: "u", Password: "p", CACert: (&fakeHarbor{server: srv}).CACert()})
	require.NoError(t, err)

	_, err = c.GetRobotAccountByID(context.Background(), 1)
	require.ErrorContains(t, err, "instead of 1")
	require.ErrorContains(t, err, "99")
	// A mismatch must not read as a deleted robot, or revocation would drop the lease and leak it.
	require.False(t, isNotFound(err))
}

func TestParseCACerts(t *testing.T) {
	valid := newFakeHarbor(t).CACert()
	corrupt := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}))

	certs, err := parseCACerts(valid)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	require.NoError(t, validateCACert(valid))

	certs, err = parseCACerts(valid + valid)
	require.NoError(t, err)
	require.Len(t, certs, 2)

	certs, err = parseCACerts(valid + "\n\n  \n")
	require.NoError(t, err)
	require.Len(t, certs, 1)

	// AppendCertsFromPEM accepts a bundle whose second certificate is corrupt; the strict parse must not.
	require.True(t, x509.NewCertPool().AppendCertsFromPEM([]byte(valid+corrupt)))

	_, err = parseCACerts("")
	require.ErrorContains(t, err, "ca_cert")

	for name, bundle := range map[string]string{
		"chain with a corrupt certificate": valid + corrupt,
		"corrupt certificate":              corrupt,
		"trailing bytes":                   valid + "-----BEGIN NONSENSE",
		"trailing garbage":                 valid + "oops\n",
		// pem.Decode skips anything before the first block, so leading garbage must be rejected too.
		"leading garbage":   "oops\n" + valid,
		"not pem at all":    "not a certificate",
		"only a key block":  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("x")})),
		"key after a chain": valid + string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("x")})),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseCACerts(bundle)
			require.ErrorContains(t, err, "ca_cert")
			require.ErrorContains(t, validateCACert(bundle), "ca_cert")
			_, err = newHTTPClient(bundle)
			require.ErrorContains(t, err, "ca_cert")
		})
	}
}
