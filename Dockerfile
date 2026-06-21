FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/go-kms ./cmd/server

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/go-kms /go-kms
EXPOSE 8080
ENTRYPOINT ["/go-kms"]
