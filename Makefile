.PHONY: build test lint race clean install deps release-dry

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/GhanshyamJha05/Sentinel/pkg/version.Version=$(VERSION) -X github.com/GhanshyamJha05/Sentinel/pkg/version.Commit=$(COMMIT) -X github.com/GhanshyamJha05/Sentinel/pkg/version.Date=$(DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o bin/sentinel .

test:
	go test ./... -count=1

race:
	go test ./... -race -count=1

lint:
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run ./... || go vet ./...

deps:
	go mod download
	go mod tidy

install:
	go install -ldflags "$(LDFLAGS)" .

clean:
	rm -rf bin/ dist/

release-dry:
	goreleaser release --snapshot --clean

self-scan: build
	./bin/sentinel scan all . --fail-on high --no-color || true
