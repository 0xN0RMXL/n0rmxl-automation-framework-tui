VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE      := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
BINARY    := bin/n0rmxl

.PHONY: all build install test test-race test-cover lint vet clean deps smoke smoke-strict release-linux ci

all: build

build:
	go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY) ./cmd/n0rmxl

install:
	go install -ldflags="$(LDFLAGS)" ./cmd/n0rmxl

test:
	go test -count=1 -timeout 120s ./...

test-race:
	@if [ "$$(go env CGO_ENABLED)" != "1" ]; then echo "[n0rmxl] skipping race tests: CGO_ENABLED is not 1"; exit 0; fi
	@if ! command -v gcc >/dev/null 2>&1; then echo "[n0rmxl] skipping race tests: gcc compiler not found"; exit 0; fi
	go test -race -count=1 -timeout 120s ./...

test-cover:
	go test -count=1 -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./... --timeout 120s

vet:
	go vet ./...

clean:
	rm -rf bin/ coverage.out coverage.html /tmp/n0rmxl_*.log

deps:
	go mod tidy && go mod download

smoke: build
	./$(BINARY) smoke example.com --preflight-only --no-tui --install=false --strict=false

smoke-strict: build
	./$(BINARY) smoke example.com --preflight-only --no-tui --install=false --strict=true

release-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	go build -ldflags="$(LDFLAGS)" -trimpath -o bin/n0rmxl-linux-amd64 ./cmd/n0rmxl
	@echo "Binary size: $$(du -sh bin/n0rmxl-linux-amd64 | cut -f1)"

ci: vet test test-race smoke-strict
