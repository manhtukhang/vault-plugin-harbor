package harbor

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

const (
	envVarRunAccTests    = "VAULT_ACC"
	envVarHarborUsername = "TEST_HARBOR_USERNAME"
	envVarHarborPassword = "TEST_HARBOR_PASSWORD"
	envVarHarborURL      = "TEST_HARBOR_URL"
	envVarHarborCACert   = "TEST_HARBOR_CA_CERT"
)

// runAcceptanceTests will separate unit tests from
// acceptance tests, which will make active requests
// to your target API.
var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

func newTestBackend(tb testing.TB, system logical.SystemView, logger hclog.Logger) (*harborBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = logger
	config.System = system

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*harborBackend), config.StorageView
}

// getTestBackend returns a backend with the default test system view (48h max lease TTL).
func getTestBackend(tb testing.TB) (*harborBackend, logical.Storage) {
	tb.Helper()
	return newTestBackend(tb, logical.TestSystemView(), hclog.NewNullLogger())
}

func getTestBackendWithMaxLeaseTTL(tb testing.TB, maxLeaseTTL time.Duration) (*harborBackend, logical.Storage) {
	tb.Helper()
	return newTestBackend(tb, &logical.StaticSystemView{
		DefaultLeaseTTLVal: min(time.Hour, maxLeaseTTL),
		MaxLeaseTTLVal:     maxLeaseTTL,
	}, hclog.NewNullLogger())
}

// logRecorder collects everything the backend logs; hclog writes from the request goroutine.
type logRecorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *logRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(p)
}

func (r *logRecorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

// getTestBackendWithLogs returns a backend logging down to Trace into the recorder.
func getTestBackendWithLogs(tb testing.TB) (*harborBackend, logical.Storage, *logRecorder) {
	tb.Helper()
	rec := &logRecorder{}
	b, s := newTestBackend(tb, logical.TestSystemView(), hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Trace,
		Output: rec,
	}))
	return b, s, rec
}

// handleWrite picks Create or Update through the existence check, as Vault core does.
func handleWrite(t *testing.T, b *harborBackend, req *logical.Request) (*logical.Response, error) {
	t.Helper()
	req.Operation = logical.CreateOperation
	_, exists, err := b.HandleExistenceCheck(context.Background(), req)
	require.NoError(t, err)
	if exists {
		req.Operation = logical.UpdateOperation
	}
	return b.HandleRequest(context.Background(), req)
}

func configureBackend(t *testing.T, b *harborBackend, s logical.Storage, f *fakeHarbor) {
	t.Helper()
	resp, err := configRequest(t, b, s, map[string]interface{}{
		"url":      f.URL(),
		"username": fakeHarborUsername,
		"password": fakeHarborPassword,
		"ca_cert":  f.CACert(),
	})
	requireNoError(t, resp, err)
}

// setRobotPrefix records Harbor's robot_name_prefix in the configuration, as a successful rotation
// does: a system robot's name is not separated from it, so it is learned no other way.
func setRobotPrefix(t *testing.T, s logical.Storage, prefix string) {
	t.Helper()
	config, err := getConfig(context.Background(), s)
	require.NoError(t, err)
	require.NotNil(t, config)
	config.RobotPrefix = prefix
	require.NoError(t, storeConfig(context.Background(), s, config))
}

func requireNoError(t *testing.T, resp *logical.Response, err error) {
	t.Helper()
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}
}

func requireErrorResponse(t *testing.T, resp *logical.Response, err error, contains string) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError(), "expected an error response, got %#v", resp)
	require.Contains(t, resp.Error().Error(), contains)
}

type closeIdleRecorder struct {
	http.RoundTripper
	closed atomic.Int32
}

func (c *closeIdleRecorder) CloseIdleConnections() {
	c.closed.Add(1)
}

func TestResetClosesIdleConnections(t *testing.T) {
	b, _ := getTestBackend(t)
	rec := &closeIdleRecorder{RoundTripper: http.DefaultTransport}
	b.client = &harborClient{http: &http.Client{Transport: rec}}

	b.reset()
	require.Nil(t, b.client)
	require.EqualValues(t, 1, rec.closed.Load())

	b.reset()
	require.EqualValues(t, 1, rec.closed.Load())
}

// acceptanceConfig returns the config of the test principal and its CA certificate.
func acceptanceConfig(t *testing.T) (map[string]interface{}, string) {
	t.Helper()
	if !runAcceptanceTests {
		t.Skipf("set %s=1 to run acceptance tests", envVarRunAccTests)
	}

	harborURL := os.Getenv(envVarHarborURL)
	username := os.Getenv(envVarHarborUsername)
	password := os.Getenv(envVarHarborPassword)
	require.NotEmpty(t, harborURL, envVarHarborURL)
	require.NotEmpty(t, username, envVarHarborUsername)
	require.NotEmpty(t, password, envVarHarborPassword)

	var caCert string
	if path := os.Getenv(envVarHarborCACert); path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // test input path from the environment
		require.NoError(t, err)
		caCert = string(data)
	}

	return map[string]interface{}{
		"url":                harborURL,
		"username":           username,
		"password":           password,
		"ca_cert":            caCert,
		"verify_connection":  true,
		"allow_all_projects": true,
	}, caCert
}

// authStatus returns the HTTP status of an authenticated Harbor call with the given credentials.
func authStatus(t *testing.T, httpClient *http.Client, harborURL, name, secret string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, harborURL+harborAPIPath+"/users/current/permissions", nil)
	require.NoError(t, err)
	req.SetBasicAuth(name, secret)
	res, err := httpClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	return res.StatusCode
}

// TestAcceptanceRobotAccount runs the full lease lifecycle against a real Harbor.
func TestAcceptanceRobotAccount(t *testing.T) {
	config, caCert := acceptanceConfig(t)
	ctx := context.Background()

	t.Run("config rejects wrong password", func(t *testing.T) {
		b, s := getTestBackend(t)
		bad := map[string]interface{}{}
		for k, v := range config {
			bad[k] = v
		}
		bad["password"] = "Wrong-Password-1"
		resp, err := configRequest(t, b, s, bad)
		requireErrorResponse(t, resp, err, "failed to verify connection")
	})

	b, s := getTestBackendWithMaxLeaseTTL(t, time.Hour)
	resp, err := configRequest(t, b, s, config)
	requireNoError(t, resp, err)

	principal, err := b.getClient(ctx, s)
	require.NoError(t, err)

	httpClient, err := newHTTPClient(caCert)
	require.NoError(t, err)
	robotStatus := func(t *testing.T, name, secret string) int {
		t.Helper()
		return authStatus(t, httpClient, principal.url, name, secret)
	}

	roles := []struct {
		name             string
		permissions      string
		level            string
		allowAllProjects bool
	}{
		{
			name:        "acc-project",
			permissions: `[{"kind":"project","namespace":"library","access":[{"resource":"repository","action":"pull","effect":"allow"}]}]`,
			level:       robotKindProject,
		},
		{
			name:             "acc-system",
			permissions:      `[{"kind":"project","namespace":"*","access":[{"resource":"repository","action":"pull"}]}]`,
			level:            robotKindSystem,
			allowAllProjects: true,
		},
	}

	for _, role := range roles {
		t.Run(role.name, func(t *testing.T) {
			resp, err := roleRequest(t, b, s, role.name, map[string]interface{}{
				"permissions":        role.permissions,
				"allow_all_projects": role.allowAllProjects,
				"ttl":                "5m",
				"max_ttl":            "30m",
			})
			requireNoError(t, resp, err)

			resp, err = b.HandleRequest(ctx, &logical.Request{
				Operation:   logical.ReadOperation,
				Path:        "creds/" + role.name,
				Storage:     s,
				DisplayName: "token-Acceptance",
			})
			requireNoError(t, resp, err)

			id := resp.Data["robot_account_id"].(int64)
			name := resp.Data["robot_account_name"].(string)
			secret := resp.Data["robot_account_secret"].(string)
			t.Cleanup(func() {
				if err := principal.DeleteRobotAccountByID(context.Background(), id); err != nil && !isNotFound(err) {
					t.Errorf("cleanup of robot account %d failed: %v", id, err)
				}
			})

			robot, err := principal.GetRobotAccountByID(ctx, id)
			require.NoError(t, err)
			require.Equal(t, name, robot.Name)
			require.Equal(t, role.level, robot.Level)

			require.Equal(t, http.StatusOK, robotStatus(t, name, secret))
			require.Equal(t, http.StatusUnauthorized, robotStatus(t, name, secret+"x"))

			leased := roundTripSecret(t, resp.Secret)

			resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.RenewOperation, Storage: s, Secret: leased})
			requireNoError(t, resp, err)
			require.Equal(t, 5*time.Minute, resp.Secret.TTL)
			require.Equal(t, 30*time.Minute, resp.Secret.MaxTTL)

			revoke := &logical.Request{Operation: logical.RevokeOperation, Storage: s, Secret: leased}
			resp, err = b.HandleRequest(ctx, revoke)
			requireNoError(t, resp, err)

			_, err = principal.GetRobotAccountByID(ctx, id)
			require.True(t, isNotFound(err), "robot account must be deleted, got %v", err)
			require.Equal(t, http.StatusUnauthorized, robotStatus(t, name, secret))

			resp, err = b.HandleRequest(ctx, revoke)
			requireNoError(t, resp, err)

			resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.DeleteOperation, Path: "roles/" + role.name, Storage: s})
			requireNoError(t, resp, err)
		})
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.DeleteOperation, Path: configStoragePath, Storage: s})
	requireNoError(t, resp, err)
}

// TestAcceptanceRotateRoot rotates a temporary clone of the test principal, never the test principal itself.
func TestAcceptanceRotateRoot(t *testing.T) {
	config, caCert := acceptanceConfig(t)
	ctx := context.Background()

	harborURL, err := normalizeURL(config["url"].(string))
	require.NoError(t, err)
	principal, err := newClient(&harborConfig{URL: harborURL, Username: config["username"].(string), Password: config["password"].(string), CACert: caCert})
	require.NoError(t, err)
	defer principal.http.CloseIdleConnections()

	deleteRobot := func(id int64) {
		if err := principal.DeleteRobotAccountByID(context.Background(), id); err != nil && !isNotFound(err) {
			t.Errorf("cleanup of robot account %d failed: %v", id, err)
		}
	}

	source, err := findRobotPrincipal(ctx, principal, &harborConfig{Username: config["username"].(string)})
	require.NoError(t, err)
	require.NotNil(t, source, "test principal must be a system robot account")

	clone, err := principal.NewRobotAccount(ctx, &harborModel.RobotCreate{
		Name:        fmt.Sprintf("acc-rotate.%d", time.Now().UnixNano()),
		Description: "vault-plugin-harbor rotate-root acceptance test",
		Duration:    1,
		Level:       source.Level,
		Permissions: source.Permissions,
	})
	require.NoError(t, err)
	principalIDs := []int64{clone.ID}
	t.Cleanup(func() {
		for _, id := range principalIDs {
			deleteRobot(id)
		}
	})

	b, s := getTestBackendWithMaxLeaseTTL(t, time.Hour)
	config["username"] = clone.Name
	config["password"] = clone.Secret
	resp, err := configRequest(t, b, s, config)
	requireNoError(t, resp, err)

	resp, err = roleRequest(t, b, s, "acc-rotate", map[string]interface{}{
		"permissions": `[{"kind":"project","namespace":"library","access":[{"resource":"repository","action":"pull"}]}]`,
		"ttl":         "5m",
		"max_ttl":     "30m",
	})
	requireNoError(t, resp, err)

	httpClient, err := newHTTPClient(caCert)
	require.NoError(t, err)

	mint := func(t *testing.T) *logical.Secret {
		t.Helper()
		resp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "creds/acc-rotate", Storage: s, DisplayName: "token-acceptance"})
		requireNoError(t, resp, err)
		id := resp.Data["robot_account_id"].(int64)
		t.Cleanup(func() { deleteRobot(id) })
		return roundTripSecret(t, resp.Secret)
	}
	revoke := func(t *testing.T, secret *logical.Secret) {
		t.Helper()
		resp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.RevokeOperation, Storage: s, Secret: secret})
		requireNoError(t, resp, err)
		id, err := leaseInt64(secret.InternalData, "robot_account_id")
		require.NoError(t, err)
		_, err = principal.GetRobotAccountByID(ctx, id)
		require.True(t, isNotFound(err), "robot account must be deleted, got %v", err)
	}

	issuedBeforeRotation := mint(t)
	previous := &harborConfig{Username: clone.Name, Password: clone.Secret}
	previousID := clone.ID

	for range 2 {
		resp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "config/rotate-root", Storage: s})
		requireNoError(t, resp, err)
		require.Empty(t, resp.Warnings)

		current := storedConfig(t, s)
		require.Equal(t, map[string]interface{}{"username": current.Username, "robot_id": current.RobotID}, resp.Data)
		require.NotEqual(t, previous.Username, current.Username)
		require.NotEqual(t, previous.Password, current.Password)

		robot, err := findRobotPrincipal(ctx, principal, current)
		require.NoError(t, err)
		require.NotNil(t, robot)
		principalIDs = append(principalIDs, robot.ID)
		require.ElementsMatch(t, flattenPermissions(source.Permissions), flattenPermissions(robot.Permissions))

		_, err = principal.GetRobotAccountByID(ctx, previousID)
		require.True(t, isNotFound(err), "previous principal must be deleted, got %v", err)
		require.Equal(t, http.StatusUnauthorized, authStatus(t, httpClient, harborURL, previous.Username, previous.Password))
		require.Equal(t, http.StatusOK, authStatus(t, httpClient, harborURL, current.Username, current.Password))

		revoke(t, mint(t))

		previous, previousID = current, robot.ID
	}

	revoke(t, issuedBeforeRotation)

	resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.DeleteOperation, Path: configStoragePath, Storage: s})
	requireNoError(t, resp, err)
}

// flattenPermissions makes permissions comparable regardless of the order Harbor returns them in.
func flattenPermissions(permissions []*harborModel.RobotPermission) []string {
	var flat []string
	for _, p := range permissions {
		for _, a := range p.Access {
			flat = append(flat, strings.Join([]string{p.Kind, p.Namespace, a.Resource, a.Action, a.Effect}, ":"))
		}
	}
	return flat
}
