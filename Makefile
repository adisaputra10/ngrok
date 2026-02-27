.PHONY: build build-server build-client run-server run-client clean dev deps

# Build all binaries
build: build-server build-client

build-server:
	go build -o bin/gotunnel-server ./cmd/server

build-client:
	go build -o bin/gotunnel ./cmd/client

# Run in development mode
run-server:
	go run ./cmd/server

run-client:
	go run ./cmd/client

# Development with hot reload (requires air: go install github.com/air-verse/air@latest)
dev:
	air -c .air.toml || go run ./cmd/server

# Install dependencies
deps:
	go mod download
	go mod tidy

# Clean build artifacts
clean:
	rm -rf bin/
	rm -rf data/

# Build for multiple platforms (server)
release-server:
	GOOS=linux GOARCH=amd64 go build -o bin/gotunnel-server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=arm64 go build -o bin/gotunnel-server-linux-arm64 ./cmd/server

# Build client binaries for all platforms (served as downloads)
release-client:
	@mkdir -p downloads
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o downloads/gotunnel-linux-amd64 ./cmd/client
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o downloads/gotunnel-linux-arm64 ./cmd/client
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o downloads/gotunnel-darwin-amd64 ./cmd/client
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o downloads/gotunnel-darwin-arm64 ./cmd/client
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o downloads/gotunnel-windows-amd64.exe ./cmd/client

# Build everything
release: release-server release-client

# Docker
docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f
