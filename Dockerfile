FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/citadel ./cmd/server

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/citadel /citadel
EXPOSE 8080
ENTRYPOINT ["/citadel"]
