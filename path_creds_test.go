package harbor

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

// newAcceptanceTestEnv creates a test environment for credentials
func newAcceptanceTestEnv() (*testEnv, error) {
	ctx := context.Background()

	maxLease, _ := time.ParseDuration("60s")
	defaultLease, _ := time.ParseDuration("30s")
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLease,
			MaxLeaseTTLVal:     maxLease,
		},
		Logger: logging.NewVaultLogger(log.Debug),
	}
	b, err := Factory(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &testEnv{
		Username: os.Getenv(envVarHarborUsername),
		Password: os.Getenv(envVarHarborPassword),
		URL:      os.Getenv(envVarHarborURL),
		Backend:  b,
		Context:  ctx,
		Storage:  &logical.InmemStorage{},
	}, nil
}

// TestAcceptanceRobotAccount tests a series of steps to make
// sure the role and token creation work correctly.
func TestAcceptanceRobotAccount(t *testing.T) {
	fmt.Printf("VAULT_ACC=%v\n", runAcceptanceTests)
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("add role", acceptanceTestEnv.AddRobotAccountRole)
	t.Run("read cred", acceptanceTestEnv.ReadRobotAccount)
	t.Run("re-read cred", acceptanceTestEnv.ReadRobotAccount)
	t.Run("revoke cred", acceptanceTestEnv.RevokeRobotAccount)
	t.Run("renew cred", acceptanceTestEnv.RenewRobotAccount)
	t.Run("cleanup robot accounts", acceptanceTestEnv.CleanupRobotAccounts)
}
