package harbor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = `
The harbor secrets backend dynamically generates Harbor robot accounts.
After mounting this backend, credentials to manage Harbor robot accounts
must be configured with the "config" endpoint.
`

// walRollbackMinAge must exceed the longest creds request, bounded by httpClientTimeout.
const walRollbackMinAge = 5 * time.Minute

var Version = "v0.0.0-dev"

var errBackendNotConfigured = errors.New("harbor backend is not configured")

// Factory configures and returns Harbor secrets backends.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// harborBackend defines an object that
// extends the Vault backend and stores the
// target API's client.
type harborBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *harborClient
	// roleLock serializes role writes so concurrent partial updates are not lost.
	roleLock sync.Mutex
	// configLock serializes config writes and root credential rotation.
	configLock sync.Mutex
}

// backend defines the target API backend
// for Vault. It must include each path
// and the secrets it will store.
func backend() *harborBackend {
	b := harborBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				configStoragePath,
				roleStoragePrefix,
				framework.WALPrefix,
			},
		},
		Paths: framework.PathAppend(
			pathRoles(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathRotateRoot(&b),
				pathCreds(&b),
			},
		),
		Secrets: []*framework.Secret{
			b.harborToken(),
		},
		BackendType:       logical.TypeLogical,
		Invalidate:        b.invalidate,
		WALRollback:       b.walRollback,
		WALRollbackMinAge: walRollbackMinAge,
		RunningVersion:    Version,
	}
	return &b
}

// reset clears any client configuration for a new
// backend to be configured
func (b *harborBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	if b.client != nil {
		b.client.http.CloseIdleConnections()
	}
	b.client = nil
}

// invalidate clears an existing client configuration in
// the backend
func (b *harborBackend) invalidate(ctx context.Context, key string) {
	if key == configStoragePath {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (b *harborBackend) getClient(ctx context.Context, s logical.Storage) (*harborClient, error) {
	b.lock.RLock()
	client := b.client
	b.lock.RUnlock()
	if client != nil {
		return client, nil
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, errBackendNotConfigured
	}

	b.client, err = newClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}
