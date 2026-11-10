# Cerberus engine: static binary in a distroless nonroot image.
# Build from the repo root: docker build -f deploy/Dockerfile -t cerberus:dev .
FROM golang:1.24-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build \
	-ldflags "-s -w -X main.version=${VERSION}" \
	-o /cerberus ./cmd/cerberus \
	&& mkdir -p /var/lib/cerberus

FROM gcr.io/distroless/static:nonroot
# /var/lib/cerberus must exist and belong to nonroot (uid 65532): distroless
# has no mkdir and the audit DB is written there when no volume is mounted.
COPY --from=build --chown=65532:65532 /var/lib/cerberus /var/lib/cerberus
COPY --from=build /cerberus /cerberus
COPY policies/ /policies/
# /data must be writable by nonroot: PUT /v1/admin/data writes a temp file
# next to the data file and renames it over (root-owned → 500 permission denied).
# With the compose bind mount, the host dir must be writable by uid 65532 too.
COPY --chown=65532:65532 data/ /data/
ENV CERBERUS_POLICY_DIR=/policies \
	CERBERUS_DATA_FILE=/data/prod.json \
	CERBERUS_AUDIT_DB=/var/lib/cerberus/cerberus.db
EXPOSE 8089
USER nonroot
ENTRYPOINT ["/cerberus"]
