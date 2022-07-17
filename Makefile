.PHONY: test \
fmt tidy gofmt gofumpt goimports lint local-lint staticcheck \
build clean

APPNAME := vault-plugin-harbor
HARBOR_VERSION = v2.5.0
TEST_HARBOR_URL = "http://localhost:30002"
TEST_HARBOR_USERNAME = admin
TEST_HARBOR_PASSWORD = Harbor12345

test:
	gotest -v ./...

integration-test:
	go clean -testcache &&\
	VAULT_ACC=1 TEST_HARBOR_URL=$(TEST_HARBOR_URL) TEST_HARBOR_USERNAME=$(TEST_HARBOR_USERNAME) TEST_HARBOR_PASSWORD=$(TEST_HARBOR_PASSWORD) gotest -v ./...

integration-test-full: setup-harbor integration-test

# Exclude auto-generated code to be formatted by gofmt, gofumpt & goimports.
FIND=find . \( -path "./examples" -o -path "./scripts" \) -prune -false -o -name '*.go'

fmt: gofmt gofumpt goimports tidy

tidy:
	go mod tidy

gofmt:
	$(FIND) -exec gofmt -l -w {} \;

gofumpt:
	$(FIND) -exec gofumpt -w {} \;

goimports:
	$(FIND) -exec goimports -w {} \;

lint:
	golint ./...

local-lint:
	docker run --rm -v $(shell pwd):/$(APPNAME) -w /$(APPNAME)/. \
	golangci/golangci-lint golangci-lint run --sort-results

staticcheck:
	staticcheck ./...

# Create a Harbor instance as a docker container via Kind.
setup-harbor:
	scripts/setup-harbor.sh $(HARBOR_VERSION) $(TEST_HARBOR_URL) $(TEST_HARBOR_USERNAME) $(TEST_HARBOR_PASSWORD)

uninstall-harbor:
	kind delete clusters "goharbor-integration-tests-$(HARBOR_VERSION)"

build:
	gorelease build --snapshot --rm-dist

clean:
	rm -rf dist/ build/
