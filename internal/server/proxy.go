package server

import (
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"gotunnel/internal/protocol"
)

// proxyHandler returns the HTTP handler for the public tunnel proxy
func (s *Server) proxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host

		// Remove port if present
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}

		// Extract subdomain
		if !strings.HasSuffix(host, "."+s.config.Domain) {
			// Not a tunnel request — could be the main domain
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		subdomain := strings.TrimSuffix(host, "."+s.config.Domain)
		if subdomain == "" || strings.Contains(subdomain, ".") {
			http.Error(w, "Invalid subdomain", http.StatusBadRequest)
			return
		}

		// Check if tunnel exists
		_, ok := s.tunnelMgr.GetConnection(subdomain)
		if !ok {
			s.renderTunnelOffline(w, subdomain)
			return
		}

		// Read request body
		var body []byte
		if r.Body != nil {
			var err error
			body, err = io.ReadAll(io.LimitReader(r.Body, 100*1024*1024)) // 100MB max
			if err != nil {
				http.Error(w, "Failed to read request body", http.StatusBadRequest)
				return
			}
		}

		// Build headers map
		headers := make(map[string][]string)
		for key, values := range r.Header {
			headers[key] = values
		}

		// Add proxy headers
		clientIP := r.RemoteAddr
		if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
			clientIP = clientIP[:idx]
		}
		headers["X-Forwarded-For"] = []string{clientIP}
		headers["X-Forwarded-Proto"] = []string{"https"}
		headers["X-Forwarded-Host"] = []string{host}
		headers["X-Real-IP"] = []string{clientIP}

		// Build the request payload
		reqPayload := &protocol.HTTPRequestPayload{
			Method:  r.Method,
			Path:    r.URL.RequestURI(),
			Host:    host,
			Headers: headers,
			Body:    body,
		}

		start := time.Now()

		// Forward through tunnel
		resp, err := s.tunnelMgr.ForwardRequest(subdomain, reqPayload)
		if err != nil {
			duration := time.Since(start)
			log.Printf("[proxy] %s %s %s -> error: %v (%s)", r.Method, host, r.URL.Path, err, duration.Round(time.Millisecond))

			// Log to DB
			tunnel, _ := s.db.GetTunnelBySubdomain(subdomain)
			if tunnel != nil {
				s.db.LogRequest(tunnel.ID, r.Method, r.URL.Path, 502, float64(duration.Milliseconds()), clientIP, r.UserAgent())
			}

			http.Error(w, "502 Bad Gateway - tunnel error: "+err.Error(), http.StatusBadGateway)
			return
		}

		duration := time.Since(start)

		// Log the request
		tunnel, _ := s.db.GetTunnelBySubdomain(subdomain)
		if tunnel != nil {
			s.db.LogRequest(tunnel.ID, r.Method, r.URL.Path, resp.StatusCode, float64(duration.Milliseconds()), clientIP, r.UserAgent())
		}

		log.Printf("[proxy] %s %s%s -> %d (%s)", r.Method, subdomain, r.URL.Path, resp.StatusCode, duration.Round(time.Millisecond))

		// Write response headers
		for key, values := range resp.Headers {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}

		// Write status and body
		w.WriteHeader(resp.StatusCode)
		if resp.Body != nil {
			w.Write(resp.Body)
		}
	})
}

// renderTunnelOffline renders a nice error page when a tunnel is not connected
func (s *Server) renderTunnelOffline(w http.ResponseWriter, subdomain string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tunnel Offline</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 text-white min-h-screen flex items-center justify-center">
    <div class="text-center">
        <div class="text-6xl mb-4">🔌</div>
        <h1 class="text-3xl font-bold mb-2">Tunnel Offline</h1>
        <p class="text-gray-400 mb-4">
            <span class="text-cyan-400 font-mono">` + subdomain + `.` + s.config.Domain + `</span> is not connected.
        </p>
        <p class="text-gray-500 text-sm">
            The tunnel client is not running or has disconnected.
        </p>
        <div class="mt-8">
            <a href="https://` + s.config.Domain + `" class="text-cyan-400 hover:text-cyan-300 text-sm">
                Powered by GoTunnel
            </a>
        </div>
    </div>
</body>
</html>`

	w.Write([]byte(html))
}
