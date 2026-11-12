# Built with the Go Cryptographic Module (GOFIPS140=certified, CMVP #5247) on the
# FIPS Go image; runs on the distroless FIPS base image as nonroot (65532).
ARG NODE_IMAGE=node:22-bookworm-slim
ARG GO_IMAGE=ghcr.io/worlddrknss/debian-fips-go:1.27.1
ARG BASE_IMAGE=ghcr.io/worlddrknss/debian-fips-base:3.5.4-pqc

# The web console is built here, from source, so an image can never ship a
# stale UI.
FROM ${NODE_IMAGE} AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/build/ ./cmd/server/webdist/
RUN CGO_ENABLED=0 GOOS=linux GOFIPS140=certified go build -trimpath -o /out/citadel ./cmd/server

FROM ${BASE_IMAGE}
COPY --from=build /out/citadel /citadel
# The base image sets GODEBUG=fips140=only: non-approved algorithms fail.
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/citadel"]
