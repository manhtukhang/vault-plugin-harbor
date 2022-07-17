package main

import (
	"os"

	harbor "github.com/manhtukhang/vault-plugin-harbor"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	logger := hclog.New(&hclog.LoggerOptions{})

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logger.Error("could not parse flags", "error", err)
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: harbor.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
