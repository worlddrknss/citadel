# Built with the Go Cryptographic Module (GOFIPS140=certified, CMVP #5247) on the
# FIPS Go image; runs on the distroless FIPS base image as nonroot (65532).
ARG GO_IMAGE=ghcr.io/worlddrknss/debian-fips-go:1.27.1
ARG BASE_IMAGE=ghcr.io/worlddrknss/debian-fips-base:3.5.4-pqc

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/citadel ./cmd/server

FROM ${BASE_IMAGE}
COPY --from=build /out/citadel /citadel
# fips140=on, not the base image's fips140=only, until the last legacy Argon2id
# password hash is gone: passwords are PBKDF2-HMAC-SHA256 now, and an Argon2id
# hash is re-hashed on its next successful login, but verifying it still uses
# Argon2 (not FIPS approved). Then drop Argon2 and switch to fips140=only.
ENV GODEBUG=fips140=on
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/citadel"]
