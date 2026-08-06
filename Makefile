# ghe-wizard Makefile
BINARY      := ghe-wizard
PKG         := ./cmd/ghe-wizard
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
	-X github.com/ghe-wizard/ghe-wizard/internal/buildinfo.Version=$(VERSION) \
	-X github.com/ghe-wizard/ghe-wizard/internal/buildinfo.Commit=$(COMMIT) \
	-X github.com/ghe-wizard/ghe-wizard/internal/buildinfo.Date=$(DATE)

.PHONY: all build run test cover vet lint fmt tidy clean docker help

all: vet test build ## vet, test and build

build: ## build the binary with version info
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

run: ## build and start the web dashboard
	go run $(PKG) serve

test: ## run tests with race detector
	go test -race -count=1 ./...

cover: ## run tests and open coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

vet: ## go vet
	go vet ./...

lint: ## run golangci-lint (must be installed)
	golangci-lint run ./...

fmt: ## format the code
	gofmt -s -w .

tidy: ## tidy modules
	go mod tidy

docker: ## build the container image
	docker build -t $(BINARY):$(VERSION) .

clean: ## remove build artifacts
	rm -f $(BINARY) $(BINARY).exe coverage.out
	rm -rf dist

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
