# Multi-stage Dockerfile for Cerberus
# Single image containing all 5 enforcement and engine binaries.

# Stage 1: Builder
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Cache dependency layer
COPY go.mod go.sum ./
RUN go mod download

# Copy source tree
COPY . .

# Build production binaries into /out/ and run sanity builds for CLI offline tools
RUN mkdir -p /out && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cerberus ./cmd/cerberus && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cerberus-tap ./cmd/cerberus-tap && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cerberus-proxy ./cmd/cerberus-proxy && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cerberus-ssh ./cmd/cerberus-ssh && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/loadgen-stress ./cmd/loadgen-stress && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dev/null ./cmd/cerberus-bundle && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dev/null ./cmd/cerberus-redteam

# Stage 2: Final runtime image
FROM alpine:3.21

# Install runtime dependencies (ca-certificates for TLS upstreams, tzdata for log timezones)
RUN apk add --no-cache ca-certificates tzdata

# Create non-root system user and group (uid/gid 10001)
RUN addgroup -g 10001 cerberus && \
    adduser -u 10001 -G cerberus -s /bin/sh -D cerberus

# Pre-create writable mount directories with non-root ownership
RUN mkdir -p /data /audit && \
    chown -R cerberus:cerberus /data /audit

# Copy binaries from builder stage
COPY --from=builder /out/* /usr/local/bin/

# Entrypoint script: passes through commands or defaults to cerberus -h
RUN printf '#!/bin/sh\nset -e\nif [ "$#" -eq 0 ]; then\n    set -- cerberus -h\nfi\nexec "$@"\n' > /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

USER cerberus

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["cerberus", "-h"]
