# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build server
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /gotunnel-server ./cmd/server

# Build client
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /gotunnel ./cmd/client

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binaries
COPY --from=builder /gotunnel-server /app/gotunnel-server
COPY --from=builder /gotunnel /app/gotunnel

# Create data directory
RUN mkdir -p /app/data

# Environment defaults
ENV GOTUNNEL_DB_PATH=/app/data/gotunnel.db
ENV GOTUNNEL_ADMIN_PORT=8080
ENV GOTUNNEL_PROXY_PORT=80

EXPOSE 8080 80

VOLUME ["/app/data"]

CMD ["/app/gotunnel-server"]
