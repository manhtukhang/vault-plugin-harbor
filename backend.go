package harbor

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = `
The harbor secrets backend dynamically generates user tokens.
After mounting this backend, credentials to manage harbor user tokens
must be configured with the "config/" endpoints.
`

// Version of the plugin
var Version = "v1.0.0"

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
				"config",
				"roles/*",
			},
		},
		Paths: framework.PathAppend(
			pathRoles(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathCreds(&b),
			},
		),
		Secrets: []*framework.Secret{
			b.harborToken(),
		},
		BackendType:    logical.TypeLogical,
		Invalidate:     b.invalidate,
		RunningVersion: Version,
	}
	return &b
}

// reset clears any client configuration for a new
// backend to be configured
func (b *harborBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears an existing client configuration in
// the backend
func (b *harborBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (b *harborBackend) getClient(ctx context.Context, s logical.Storage) (*harborClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock

	//nolint:gocritic
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(harborConfig)
	}

	b.client, err = newClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}
