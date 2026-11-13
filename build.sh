#!/usr/bin/env bash
# build.sh — SATU script build semua Cerberus.
# Usage:
#   ./build.sh              -> gate default: lint + test race + vet + gofmt + opa
#   ./build.sh quick        -> build binary saja (tanpa gate)
#   ./build.sh image        -> build Docker image (Dockerfile multi-stage)
#   ./build.sh dist         -> cross-compile semua platform (release)
#   ./build.sh all          -> gate + dist + image
set -euo pipefail
cd "$(dirname "$0")"

VERSION="$(git describe --tags --always 2>/dev/null || echo dev)"
BINS=(cerberus cerberus-tap cerberus-proxy cerberus-ssh cerberus-bundle cerberus-redteam loadgen-stress)
IMAGE_REPO="${CERBERUS_IMAGE:-ghcr.io/metabbe3/cerberus}"
PLATFORMS=("linux/amd64" "linux/arm64" "darwin/arm64")

c_ok()   { printf '\033[32m✔\033[0m %s\n' "$*"; }
c_step() { printf '\033[1;34m▶\033[0m %s\n' "$*"; }
c_fail() { printf '\033[31m✘ FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

build_binaries() {
    c_step "Build ${#BINS[@]} binary (CGO off, versi ${VERSION})"
    mkdir -p bin
    for b in "${BINS[@]}"; do
        CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "bin/${b}" "./cmd/${b}"
        c_ok "bin/${b}"
    done
}

gate() {
    c_step "Gate: gofmt"
    [ -z "$(gofmt -l cmd/ pkg/ internal/)" ] || c_fail "gofmt: file perlu format — jalankan: gofmt -w cmd/ pkg/ internal/"
    c_ok "gofmt bersih"

    c_step "Gate: go vet"
    go vet ./... || c_fail "go vet"
    c_ok "go vet"

    c_step "Gate: golangci-lint"
    golangci-lint run || c_fail "golangci-lint (lihat detail di atas)"
    c_ok "golangci-lint 0 issue"

    c_step "Gate: test -race (semua paket)"
    go test -race -count=1 ./... || c_fail "test -race"
    c_ok "test -race semua paket PASS"

    if command -v opa >/dev/null 2>&1; then
        c_step "Gate: OPA policy"
        opa check --strict policies/ || c_fail "opa check"
        opa test policies/ >/dev/null || c_fail "opa test"
        c_ok "opa check + test"
    else
        printf '  (opa tidak terpasang — skip)\n'
    fi
}

build_image() {
    c_step "Build image ${IMAGE_REPO}:${VERSION}"
    docker build -t "${IMAGE_REPO}:${VERSION}" -t "${IMAGE_REPO}:latest" . || c_fail "docker build"
    c_ok "image: ${IMAGE_REPO}:${VERSION} + :latest"
    printf '  Ukuran: '; docker image ls "${IMAGE_REPO}" --format '{{.Repository}}:{{.Tag}} {{.Size}}' | head -2
}

build_dist() {
    c_step "Cross-compile ${#PLATFORMS[@]} platform"
    mkdir -p dist
    for pf in "${PLATFORMS[@]}"; do
        os="${pf%/*}"; arch="${pf#*/}"
        for b in "${BINS[@]}"; do
            CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
                -ldflags "-s -w -X main.version=${VERSION}" \
                -o "dist/${b}-${os}-${arch}" "./cmd/${b}"
        done
        c_ok "dist/ ${os}/${arch} (${#BINS[@]} binary)"
    done
}

case "${1:-gate}" in
    quick) build_binaries ;;
    gate)  gate && build_binaries ;;
    image) build_image ;;
    dist)  build_dist ;;
    all)   gate && build_binaries && build_dist && build_image ;;
    *)
        sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
        exit 1
        ;;
esac
c_ok "SELESAI — mode: ${1:-gate}"
