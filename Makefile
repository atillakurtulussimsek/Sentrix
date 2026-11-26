GO        ?= go
PKG       := github.com/atillakurtulussimsek/Sentrix
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -s -w -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT) -X $(PKG)/internal/version.Date=$(DATE)
BIN       := bin

.PHONY: all build build-linux test race lint vet run-server run-agent e2e css clean

all: build test lint

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/ ./cmd/...
	$(GO) vet ./...

build-linux:
	for arch in amd64 arm64; do \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/linux_$$arch/ ./cmd/... ; \
	done

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

lint:
	golangci-lint run ./...

vet:
	$(GO) vet ./...

run-server: build
	./$(BIN)/sentrix-server --config deploy/dev/server.yaml

run-agent: build
	./$(BIN)/sentrix-agent --config deploy/dev/agent.yaml

# Requires Docker: spins up server + distro agents (test/e2e/docker-compose.yml).
e2e:
	./test/e2e/run.sh

# Regenerates the committed Tailwind stylesheet (needs Node.js).
css:
	npx --yes @tailwindcss/cli@4 -i web/tailwind.css -o web/static/app.css --minify

clean:
	rm -rf $(BIN) dist coverage.out
