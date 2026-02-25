.PHONY: build test lint clean install

BINARY := agentguard
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X github.com/aqubia/agent-guard/cmd/agentguard/cli.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/agentguard

install:
	go install $(LDFLAGS) ./cmd/agentguard

test:
	go test -race -count=1 ./...

test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/ coverage.out coverage.html

fmt:
	gofmt -s -w .

vet:
	go vet ./...
