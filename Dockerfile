# Built with the Go Cryptographic Module (GOFIPS140=certified, CMVP #5247) on the
# FIPS Go image; runs on the distroless FIPS base image as nonroot (65532).
ARG NODE_IMAGE=node:22-bookworm-slim
ARG GO_IMAGE=ghcr.io/worlddrknss/debian-fips-go:1.27.1
ARG BASE_IMAGE=ghcr.io/worlddrknss/debian-fips-base:3.5.4-pqc

# The web console is built here, from source, so an image can never ship a
# stale UI.
# Platform-independent output: build it once, natively.
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# The console's /docs pages are built from the repository's docs/*.md.
COPY docs/ /docs/
RUN npm run build

# Cross-compile on the build machine's own architecture (no emulation).
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/build/ ./cmd/server/webdist/
# The release workflow passes the tag's version; local builds report "dev".
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} GOFIPS140=certified go build -trimpath \
    -ldflags "-X github.com/worlddrknss/citadel/internal/server.buildVersion=${VERSION}" \
    -o /out/citadel ./cmd/server

FROM ${BASE_IMAGE}
COPY --from=build /out/citadel /citadel
# The base image sets GODEBUG=fips140=only: non-approved algorithms fail.
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/citadel"]
