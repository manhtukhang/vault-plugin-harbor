package main

import (
	"os"

	harbor "github.com/manhtukhang/vault-plugin-harbor"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: harbor.Factory,
	}); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	logger := hclog.New(&hclog.LoggerOptions{})
	logger.Error("plugin shutting down", "error", err)
	os.Exit(1)
}
