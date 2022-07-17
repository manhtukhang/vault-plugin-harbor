package harbor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	envVarRunAccTests    = "VAULT_ACC"
	envVarHarborUsername = "TEST_HARBOR_USERNAME"
	envVarHarborPassword = "TEST_HARBOR_PASSWORD"
	envVarHarborURL      = "TEST_HARBOR_URL"
)

// getTestBackend will help you construct a test backend object.
// Update this function with your target backend.
func getTestBackend(tb testing.TB) (*harborBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*harborBackend), config.StorageView
}

// runAcceptanceTests will separate unit tests from
// acceptance tests, which will make active requests
// to your target API.
var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

// testEnv creates an object to store and track testing environment
// resources
type testEnv struct {
	Username string
	Password string
	URL      string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	// SecretToken tracks the API token, for checking rotations
	SecretToken string

	// Tokens tracks the generated tokens, to make sure we clean up
	Tokens []string
}

// AddConfig adds the configuration to the test backend.
// Make sure data includes all of the configuration
// attributes you need and the `config` path!
func (e *testEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"username": e.Username,
			"password": e.Password,
			"url":      e.URL,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

// AddRobotAccountRole adds a role for the Harbor robot account
func (e *testEnv) AddRobotAccountRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"name":    "test-role",
			"ttl":     "30",
			"max_ttl": "60",
			"permissions": `
                [
                    {
                        "namespace": "public",
                        "access":
                        [
                            {
                                "action": "pull",
                                "resource": "repository"
                            }
                        ],
                        "kind": "project"
                    }
                ]
            `,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

// ReadRobotAccount retrieves the robot account
// based on a Vault role.
func (e *testEnv) ReadRobotAccount(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)

	if t, ok := resp.Data["robot_account_name"]; ok {
		e.Tokens = append(e.Tokens, t.(string))
	}
	require.NotEmpty(t, resp.Data["robot_account_name"])

	if e.SecretToken != "" {
		require.NotEqual(t, e.SecretToken, resp.Data["robot_account_name"])
	}

	// collect secret IDs to revoke at end of test
	require.NotNil(t, resp.Secret)
	if t, ok := resp.Secret.InternalData["robot_account_name"]; ok {
		e.SecretToken = t.(string)
	}
}

// RevokeRobotAccount revokes the robot account
// based on a Vault role.
func (e *testEnv) RevokeRobotAccount(t *testing.T) {
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, readReq)
	require.Nil(t, err)
	require.NotNil(t, resp)

	secret := resp.Secret
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Secret:    secret,
		Storage:   e.Storage,
	}

	resp, err = e.Backend.HandleRequest(e.Context, revokeReq)

	require.NoError(t, err)
	require.Nil(t, resp)
}

// RenewRobotAccount renews the robot account
// based on a Vault role.
func (e *testEnv) RenewRobotAccount(t *testing.T) {
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, readReq)
	require.Nil(t, err)
	require.NotNil(t, resp)

	if t, ok := resp.Data["robot_account_name"]; ok {
		e.Tokens = append(e.Tokens, t.(string))
	}

	secret := resp.Secret
	renewReq := &logical.Request{
		Operation: logical.RenewOperation,
		Secret:    secret,
		Storage:   e.Storage,
	}

	resp, err = e.Backend.HandleRequest(e.Context, renewReq)

	require.NoError(t, err)
	require.NotNil(t, resp)
}

// CleanupRobotAccounts removes the robot account
// when the test completes.
func (e *testEnv) CleanupRobotAccounts(t *testing.T) {
	if len(e.Tokens) == 0 {
		t.Fatalf("expected 2 tokens, got: %d", len(e.Tokens))
	}

	for _, token := range e.Tokens {
		tk := strings.Split(token, "$")[1]
		b := e.Backend.(*harborBackend)

		client, err := b.getClient(e.Context, e.Storage)
		if err != nil {
			t.Fatal("fatal getting client")
		}
		if err := client.DeleteRobotAccountByName(context.Background(), tk); err != nil {
			t.Fatalf("unexpected error deleting user token: %s", err)
		}
	}
}
