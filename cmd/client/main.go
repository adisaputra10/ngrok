package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"gotunnel/internal/protocol"

	"github.com/gorilla/websocket"
)

const version = "1.0.0"

// defaultServerURL is the pre-configured server for demolocal.online.
// Uses wss:// (port 443) automatically when no port is specified.
const defaultServerURL = "demolocal.online"

// Config holds client configuration
type Config struct {
	ServerURL string `json:"server_url"`
	AuthToken string `json:"auth_token"`
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	// Handle special commands
	switch args[0] {
	case "auth":
		if len(args) < 2 {
			fmt.Println("Usage: demolocal auth <token>")
			os.Exit(1)
		}
		handleAuth(args[1])
		return
	case "config":
		handleConfigShow()
		return
	case "version", "--version", "-v":
		fmt.Printf("demolocal v%s\n", version)
		return
	case "help", "--help", "-h":
		printUsage()
		return
	}

	// Normal tunnel mode: gotunnel <subdomain> <port>
	if len(args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subdomain := strings.ToLower(args[0])
	localPort := args[1]

	// Parse optional flags
	serverURL := ""
	authToken := ""
	for i := 2; i < len(args); i++ {
		switch {
		case args[i] == "--server" && i+1 < len(args):
			serverURL = args[i+1]
			i++
		case args[i] == "--token" && i+1 < len(args):
			authToken = args[i+1]
			i++
		}
	}

	// Load config
	config := loadConfig()
	if serverURL != "" {
		config.ServerURL = serverURL
	}
	if authToken != "" {
		config.AuthToken = authToken
	}

	if config.AuthToken == "" {
		fmt.Println("Error: auth token not set.")
		fmt.Println()
		fmt.Println("Run: demolocal auth <your-token>")
		fmt.Println("Find your token at: https://demolocal.online/dashboard/install")
		os.Exit(1)
	}

	startTunnel(config, subdomain, localPort)
}

func printUsage() {
	fmt.Printf(`demolocal v%s — Expose local services to the internet

Usage:
  demolocal <subdomain> <port> [options]
  demolocal auth <token>                  Save auth token (server: demolocal.online)
  demolocal config                        Show current config

Options:
  --server <url>    Override server URL (default: demolocal.online via wss://)
  --token <token>   Auth token (overrides saved config)
  --version, -v     Show version
  --help, -h        Show help

Examples:
  demolocal auth gt_abc123...             # Save token, ready to tunnel
  demolocal myapp 3000                    # https://myapp.demolocal.online → localhost:3000
  demolocal api 8080                      # https://api.demolocal.online → localhost:8080
  demolocal myapp 3000 --server localhost:8080  # local dev (ws://)
`, version)
}

func configDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".demolocal")
}

func configPath() string {
	return filepath.Join(configDir(), "config.json")
}

func loadConfig() Config {
	config := Config{ServerURL: defaultServerURL}
	data, err := os.ReadFile(configPath())
	if err != nil {
		return config
	}
	json.Unmarshal(data, &config)
	if config.ServerURL == "" {
		config.ServerURL = defaultServerURL
	}
	// Migrate legacy configs that have port appended (e.g. demolocal.online:8080 → demolocal.online)
	// Port 8080/80 are admin/HTTP ports; production tunnels use WSS on 443 (no port needed)
	if strings.HasSuffix(config.ServerURL, ":8080") || strings.HasSuffix(config.ServerURL, ":80") {
		config.ServerURL = config.ServerURL[:strings.LastIndex(config.ServerURL, ":")]
	}
	return config
}

func saveConfig(config Config) error {
	dir := configDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), data, 0600)
}

func handleAuth(token string) {
	config := loadConfig()
	config.AuthToken = token

	// Allow --server override; otherwise keep defaultServerURL from loadConfig
	for i, arg := range os.Args {
		if arg == "--server" && i+1 < len(os.Args) {
			config.ServerURL = os.Args[i+1]
			break
		}
	}

	if err := saveConfig(config); err != nil {
		fmt.Printf("Error saving config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Auth token saved")
	fmt.Printf("  Config: %s\n", configPath())
	fmt.Printf("  Server: %s\n", config.ServerURL)
	fmt.Println()
	fmt.Println("You can now create tunnels:")
	hostname := strings.SplitN(config.ServerURL, ":", 2)[0]
	fmt.Printf("  demolocal myapp 3000    # → https://myapp.%s\n", hostname)
}

func handleConfigShow() {
	config := loadConfig()
	fmt.Printf("Config file: %s\n", configPath())
	fmt.Printf("Server URL:  %s\n", config.ServerURL)
	if config.AuthToken != "" {
		// Show first 10 chars + masked
		if len(config.AuthToken) > 10 {
			fmt.Printf("Auth Token:  %s...%s\n", config.AuthToken[:10], strings.Repeat("*", 8))
		} else {
			fmt.Printf("Auth Token:  %s\n", config.AuthToken)
		}
	} else {
		fmt.Println("Auth Token:  (not set)")
	}
}

func startTunnel(config Config, subdomain, localPort string) {
	fmt.Println()
	fmt.Printf("Demolocal v%s\n", version)
	fmt.Println()
	fmt.Printf("Connecting to %s...", config.ServerURL)

	// Build WebSocket URL:
	//   - already has scheme (ws:// / wss://)  → use as-is
	//   - host:443                             → wss://host
	//   - host:port (other ports)              → ws://host:port  (local/dev)
	//   - plain domain (no port, no scheme)    → wss://domain    (production, port 443)
	var serverHost string
	switch {
	case strings.Contains(config.ServerURL, "://"):
		serverHost = config.ServerURL
		serverHost = strings.Replace(serverHost, "https://", "wss://", 1)
		serverHost = strings.Replace(serverHost, "http://", "ws://", 1)
	case strings.HasSuffix(config.ServerURL, ":443"):
		// Explicit port 443 — use wss:// without the port
		serverHost = "wss://" + strings.TrimSuffix(config.ServerURL, ":443")
	case strings.Contains(config.ServerURL, ":"):
		// host:port (non-443) — plain WS for local/dev
		serverHost = "ws://" + config.ServerURL
	default:
		// plain domain — use WSS (TLS on port 443)
		serverHost = "wss://" + config.ServerURL
	}
	fmt.Printf(" (%s)\n", serverHost)

	wsURL := fmt.Sprintf("%s/ws/tunnel?token=%s", serverHost, url.QueryEscape(config.AuthToken))

	// Connect WebSocket
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		fmt.Printf("Error: Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send tunnel init
	initPayload := protocol.TunnelInitPayload{
		AuthToken: config.AuthToken,
		Subdomain: subdomain,
		LocalPort: parseInt(localPort),
		Version:   version,
	}

	initMsg, _ := protocol.NewMessage(protocol.TypeTunnelInit, "", initPayload)
	initData, _ := json.Marshal(initMsg)
	if err := conn.WriteMessage(websocket.TextMessage, initData); err != nil {
		fmt.Printf("Error: Failed to send init: %v\n", err)
		os.Exit(1)
	}

	// Read response
	_, msg, err := conn.ReadMessage()
	if err != nil {
		fmt.Printf("Error: Failed to read response: %v\n", err)
		os.Exit(1)
	}

	var response protocol.Message
	json.Unmarshal(msg, &response)

	if response.Type == protocol.TypeTunnelError {
		var errPayload protocol.TunnelErrorPayload
		response.ParsePayload(&errPayload)
		fmt.Printf("Error: %s\n", errPayload.Error)
		os.Exit(1)
	}

	if response.Type != protocol.TypeTunnelReady {
		fmt.Printf("Error: Unexpected response: %s\n", response.Type)
		os.Exit(1)
	}

	var ready protocol.TunnelReadyPayload
	response.ParsePayload(&ready)

	fmt.Printf("Session Status:  \033[32monline\033[0m\n")
	fmt.Printf("Forwarding:      %s → localhost:%s\n", ready.URL, localPort)
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop the tunnel.")
	fmt.Println()

	// Handle Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	doneCh := make(chan struct{})
	requestCount := int64(0)
	var writeMu sync.Mutex

	// Safe write helper
	writeMsg := func(messageType int, data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteMessage(messageType, data)
	}

	// Process incoming requests
	go func() {
		defer close(doneCh)
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					fmt.Printf("\nConnection lost: %v\n", err)
				}
				return
			}

			var message protocol.Message
			if err := json.Unmarshal(msg, &message); err != nil {
				continue
			}

			switch message.Type {
			case protocol.TypeHTTPRequest:
				requestCount++
				go handleHTTPRequest(writeMsg, &message, localPort, requestCount)

			case protocol.TypePing:
				pongMsg, _ := protocol.NewMessage(protocol.TypePong, "", nil)
				pongData, _ := json.Marshal(pongMsg)
				writeMsg(websocket.TextMessage, pongData)
			}
		}
	}()

	// Wait for signal or disconnect
	select {
	case <-sigCh:
		fmt.Println("\nShutting down tunnel...")
		writeMu.Lock()
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		writeMu.Unlock()
	case <-doneCh:
	}

	fmt.Println("Tunnel closed.")
}

func handleHTTPRequest(writeMsg func(int, []byte) error, message *protocol.Message, localPort string, reqNum int64) {
	var req protocol.HTTPRequestPayload
	if err := message.ParsePayload(&req); err != nil {
		log.Printf("Invalid request payload: %v", err)
		sendErrorResponse(writeMsg, message.ID, 500, "Invalid request")
		return
	}

	start := time.Now()

	// Forward to local service
	targetURL := fmt.Sprintf("http://localhost:%s%s", localPort, req.Path)

	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequest(req.Method, targetURL, bodyReader)
	if err != nil {
		sendErrorResponse(writeMsg, message.ID, 502, "Failed to create request")
		return
	}

	// Set headers
	for key, values := range req.Headers {
		for _, v := range values {
			httpReq.Header.Add(key, v)
		}
	}
	httpReq.Header.Set("Host", fmt.Sprintf("localhost:%s", localPort))

	// Make the request
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		duration := time.Since(start)
		fmt.Printf("%s %s %-7s %s → \033[31m502\033[0m (%s)\n",
			time.Now().Format("15:04:05"), colorMethod(req.Method), req.Method, req.Path, duration.Round(time.Millisecond))
		sendErrorResponse(writeMsg, message.ID, 502, "Local service unavailable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024)) // 100MB max
	if err != nil {
		sendErrorResponse(writeMsg, message.ID, 502, "Failed to read response body")
		return
	}

	// Build response headers
	headers := make(map[string][]string)
	for key, values := range resp.Header {
		headers[key] = values
	}

	duration := time.Since(start)

	// Log request
	statusColor := "\033[32m" // green
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		statusColor = "\033[33m" // yellow
	} else if resp.StatusCode >= 500 {
		statusColor = "\033[31m" // red
	} else if resp.StatusCode >= 300 {
		statusColor = "\033[36m" // cyan
	}

	fmt.Printf("%s %s %-7s %s → %s%d\033[0m (%s)\n",
		time.Now().Format("15:04:05"), colorMethod(req.Method), req.Method, req.Path,
		statusColor, resp.StatusCode, duration.Round(time.Millisecond))

	// Send response back through tunnel
	respPayload := protocol.HTTPResponsePayload{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
	}

	respMsg, _ := protocol.NewMessage(protocol.TypeHTTPResponse, message.ID, respPayload)
	respData, _ := json.Marshal(respMsg)
	writeMsg(websocket.TextMessage, respData)
}

func sendErrorResponse(writeMsg func(int, []byte) error, requestID string, status int, errMsg string) {
	respPayload := protocol.HTTPResponsePayload{
		StatusCode: status,
		Headers:    map[string][]string{"Content-Type": {"text/plain"}},
		Body:       []byte(errMsg),
	}
	respMsg, _ := protocol.NewMessage(protocol.TypeHTTPResponse, requestID, respPayload)
	respData, _ := json.Marshal(respMsg)
	writeMsg(websocket.TextMessage, respData)
}

func colorMethod(method string) string {
	switch method {
	case "GET":
		return "\033[34m"
	case "POST":
		return "\033[35m"
	case "PUT", "PATCH":
		return "\033[33m"
	case "DELETE":
		return "\033[31m"
	default:
		return "\033[37m"
	}
}

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
