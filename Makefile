VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)

.PHONY: build build-all test test-full lint opa-test opa-check bench smoke

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/cerberus ./cmd/cerberus
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/cerberus-proxy ./cmd/cerberus-proxy
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/cerberus-egress ./cmd/cerberus-egress
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/cerberus-exec ./cmd/cerberus-exec
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/cerberus-tap ./cmd/cerberus-tap
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/cerberus-ssh ./cmd/cerberus-ssh
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/cerberus-bundle ./cmd/cerberus-bundle
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/cerberus-redteam ./cmd/cerberus-redteam
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/cerberus-montecarlo ./cmd/cerberus-montecarlo

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

build-all:
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "Building cerberus for $$os/$$arch..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "-s -w -X main.version=$(VERSION)" -o dist/cerberus-$$os-$$arch$$ext ./cmd/cerberus || exit 1; \
		echo "Building cerberus-proxy for $$os/$$arch..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "-s -w -X main.version=$(VERSION)" -o dist/cerberus-proxy-$$os-$$arch$$ext ./cmd/cerberus-proxy || exit 1; \
	done
	@echo "Build complete. Artifacts in dist/:"
	@ls -lh dist/

test:
# CERBERUS_SKIP_POLICY_SUITE=1: unit tests skip the in-process rego suite
# (247 tests; minutes under -race on 2-core CI). Suite enforcement stays in
# `make opa-test` + the race step below exercises it via t.Setenv force-ON tests.
	CERBERUS_SKIP_POLICY_SUITE=1 go test -race -count=1 -timeout=25m ./...

test-full:
	go test -race -count=1 -timeout=25m ./...

lint:
	golangci-lint run

opa-test:
	opa test policies/ -v

opa-check:
	opa check --strict policies/

bench:
	go test -run '^$$' -bench=. -benchmem ./internal/engine

smoke:
	scripts/smoke.sh
