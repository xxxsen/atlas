# Atlas build, verification, and local development entry points.

BIN ?= atlas
GO_VERSION ?= 1.26.5

PROJECT_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
GO ?= $(PROJECT_ROOT)/.cache/go-runtime/bin/go
GOCACHE ?= $(PROJECT_ROOT)/.cache/go-build
GOMODCACHE ?= $(PROJECT_ROOT)/.cache/go-mod
GO_ENV := GOTOOLCHAIN=local GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: help toolchain build test test-race vet fuzz-smoke check dev smoke docker-build clean

help: ## Show available commands.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

toolchain: ## Install the pinned local Go toolchain when GO is not overridden.
	@if [ "$(GO)" = "$(PROJECT_ROOT)/.cache/go-runtime/bin/go" ]; then \
		ATLAS_GO_VERSION=$(GO_VERSION) $(PROJECT_ROOT)/scripts/ensure-go.sh; \
	elif [ ! -x "$(GO)" ] && ! command -v "$(GO)" >/dev/null 2>&1; then \
		echo "Go executable not found: $(GO)" >&2; exit 1; \
	fi

build: toolchain ## Build bin/$(BIN).
	@mkdir -p $(PROJECT_ROOT)/bin
	$(GO_ENV) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(PROJECT_ROOT)/bin/$(BIN) ./cmd/atlas

test: toolchain ## Run all unit and integration tests.
	$(GO_ENV) $(GO) test ./...

test-race: toolchain ## Run all tests with the Go race detector.
	$(GO_ENV) $(GO) test -race ./...

vet: toolchain ## Run go vet for all packages.
	$(GO_ENV) $(GO) vet ./...

fuzz-smoke: toolchain ## Run a short parser fuzz smoke test.
	$(GO_ENV) $(GO) test ./internal/data/geosite -run '^$$' -fuzz '^FuzzParseGeoSiteList$$' -fuzztime 10s

check: build test test-race vet ## Run the complete local quality gate.

dev: toolchain ## Start the deterministic local upstream and Atlas DNS server.
	GOTOOLCHAIN=local ATLAS_GO="$(GO)" GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" $(PROJECT_ROOT)/scripts/dev.sh

smoke: ## Run end-to-end checks against a running make dev server.
	$(PROJECT_ROOT)/scripts/smoke.sh

docker-build: ## Build the local non-root container image.
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_DATE=$(BUILD_DATE) -t atlas:dev $(PROJECT_ROOT)

clean: ## Remove generated binaries and local development data.
	rm -rf $(PROJECT_ROOT)/bin $(PROJECT_ROOT)/.dev-data
