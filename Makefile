SHELL := bash
.SHELLFLAGS := -euo pipefail -c

MODULE := github.com/manhtukhang/vault-plugin-harbor
APPNAME := vault-plugin-harbor
VERSION ?= v0.0.0-dev

GOLANGCI_LINT_VERSION := v2.13.2
GOVULNCHECK_VERSION := v1.8.0

KIND_ENV := tmp/kind/env.sh

.PHONY: build test lint vuln fmt tidy clean kind-up kind-down plugin-register testacc

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X $(MODULE).Version=$(VERSION)" -o bin/$(APPNAME) ./cmd/$(APPNAME)

test:
	go test -race -count=1 ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

fmt:
	go fmt ./...

tidy:
	go mod tidy

# Only the binary: removing bin/ itself detaches it from the kind node bind mount.
clean:
	rm -f bin/$(APPNAME)
	rm -rf dist/

kind-up:
	scripts/kind-up.sh

kind-down:
	scripts/kind-down.sh

plugin-register: build
	scripts/plugin-register.sh $(VERSION)

testacc:
	@test -s $(KIND_ENV) || { echo "$(KIND_ENV) not found: run make kind-up" >&2; exit 1; }
	. ./$(KIND_ENV) && VAULT_ACC=1 go test -count=1 -v -run Acceptance ./...
