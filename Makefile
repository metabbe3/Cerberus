VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)

.PHONY: build test lint opa-test opa-check bench smoke

build:
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/cerberus ./cmd/cerberus

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run

opa-test:
	opa test policies/ -v

opa-check:
	opa check --strict policies/

bench:
	go test -run=^$ -bench=. -benchmem ./internal/engine

smoke:
	scripts/smoke.sh
