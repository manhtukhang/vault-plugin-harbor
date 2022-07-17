package harbor

import (
	"errors"
	"fmt"

	harbor "github.com/mittwald/goharbor-client/v5/apiv2"
	harborCfg "github.com/mittwald/goharbor-client/v5/apiv2/pkg/config"
)

// harborClient creates an object storing
// the client.
type harborClient struct {
	*harbor.RESTClient
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

	c, err := harbor.NewRESTClientForHost(
		fmt.Sprintf("%s/api/v2.0", config.URL),
		config.Username,
		config.Password,
		&harborCfg.Options{PageSize: 100},
	)
	if err != nil {
		return nil, err
	}

	return &harborClient{c}, nil
}
