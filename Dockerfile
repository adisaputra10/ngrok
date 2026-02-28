# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build server (linux/amd64 – the container target)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /gotunnel-server ./cmd/server

# Cross-compile client binaries for all platforms
RUN mkdir -p /downloads && \
    CGO_ENABLED=0 GOOS=linux   GOARCH=amd64  go build -ldflags="-s -w" -o /downloads/demolocal-linux-amd64   ./cmd/client && \
    CGO_ENABLED=0 GOOS=linux   GOARCH=arm64  go build -ldflags="-s -w" -o /downloads/demolocal-linux-arm64   ./cmd/client && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64  go build -ldflags="-s -w" -o /downloads/demolocal-darwin-amd64  ./cmd/client && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64  go build -ldflags="-s -w" -o /downloads/demolocal-darwin-arm64  ./cmd/client && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64  go build -ldflags="-s -w" -o /downloads/demolocal-windows-amd64.exe ./cmd/client

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy server binary
COPY --from=builder /gotunnel-server /app/gotunnel-server

# Copy pre-built client binaries so /download/ route works
COPY --from=builder /downloads /app/downloads

# Create data directory
RUN mkdir -p /app/data /app/data/certs

# Environment defaults
ENV GOTUNNEL_DB_TYPE=sqlite
ENV GOTUNNEL_SQLITE_DB_PATH=/app/data/gotunnel.db
ENV GOTUNNEL_ADMIN_PORT=8080
ENV GOTUNNEL_PROXY_PORT=80

EXPOSE 8080 80 443

VOLUME ["/app/data"]

CMD ["/app/gotunnel-server"]
