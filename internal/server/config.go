package server

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Config holds the server configuration
type Config struct {
	Domain            string
	AdminPort         string
	ProxyPort         string
	Secret            string
	DBPath            string
	AllowRegistration bool
	TLSCert           string
	TLSKey            string
	AutoTLS           bool   // Enable automatic TLS via ZeroSSL/ACME
	AutoTLSEmail      string // Email for ACME registration
	AutoTLSDir        string // Directory to cache certificates
	ZeroSSLAPIKey     string // ZeroSSL EAB API key (optional, uses Let's Encrypt if empty)
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	return &Config{
		Domain:            getEnv("GOTUNNEL_DOMAIN", "demolocal.online"),
		AdminPort:         getEnv("GOTUNNEL_ADMIN_PORT", "8080"),
		ProxyPort:         getEnv("GOTUNNEL_PROXY_PORT", "8081"),
		Secret:            getEnv("GOTUNNEL_SECRET", "change-me-to-a-random-secret"),
		DBPath:            getEnv("GOTUNNEL_DB_PATH", "./data/gotunnel.db"),
		AllowRegistration: getEnv("GOTUNNEL_ALLOW_REGISTRATION", "true") == "true",
		TLSCert:           getEnv("GOTUNNEL_TLS_CERT", ""),
		TLSKey:            getEnv("GOTUNNEL_TLS_KEY", ""),
		AutoTLS:           getEnv("GOTUNNEL_AUTO_TLS", "") == "true",
		AutoTLSEmail:      getEnv("GOTUNNEL_AUTO_TLS_EMAIL", ""),
		AutoTLSDir:        getEnv("GOTUNNEL_AUTO_TLS_DIR", "./data/certs"),
		ZeroSSLAPIKey:     getEnv("GOTUNNEL_ZEROSSL_API_KEY", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// LoadDotEnv loads a .env file into environment variables
func LoadDotEnv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // .env file is optional
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		// Don't override existing env vars
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}
}

// StartServers starts both the admin and proxy servers
func (s *Server) StartServers() error {
	adminHandler := s.adminHandler()
	proxyHandler := s.proxyHandler()

	// Auto TLS mode (ZeroSSL / Let's Encrypt)
	if s.config.AutoTLS {
		return s.startWithAutoTLS(adminHandler, proxyHandler)
	}

	// Start proxy server in background
	go func() {
		proxyAddr := ":" + s.config.ProxyPort
		log.Printf("[proxy] Listening on %s (tunnel traffic)", proxyAddr)
		proxyServer := &http.Server{
			Addr:    proxyAddr,
			Handler: proxyHandler,
		}
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[proxy] Server error: %v", err)
		}
	}()

	// Start admin server
	adminAddr := ":" + s.config.AdminPort
	log.Printf("[admin] Listening on %s (dashboard & API)", adminAddr)
	log.Printf("[admin] Dashboard: http://localhost%s", adminAddr)
	log.Printf("[admin] Domain: %s", s.config.Domain)
	fmt.Println()

	adminServer := &http.Server{
		Addr:    adminAddr,
		Handler: adminHandler,
	}

	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		return adminServer.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}
	return adminServer.ListenAndServe()
}

// startWithAutoTLS starts servers with automatic certificate management (ZeroSSL or Let's Encrypt)
func (s *Server) startWithAutoTLS(adminHandler, proxyHandler http.Handler) error {
	domain := s.config.Domain
	wildcardDomain := "*." + domain

	log.Printf("[tls] Auto-TLS enabled for %s and %s", domain, wildcardDomain)
	log.Printf("[tls] Certificate cache: %s", s.config.AutoTLSDir)

	// Configure ACME client
	var acmeClient *acme.Client
	var eab *acme.ExternalAccountBinding

	if s.config.ZeroSSLAPIKey != "" {
		// ZeroSSL with EAB credentials
		log.Printf("[tls] Using ZeroSSL ACME directory")
		eabKID, eabHMAC, err := getZeroSSLEAB(s.config.ZeroSSLAPIKey)
		if err != nil {
			return fmt.Errorf("failed to get ZeroSSL EAB credentials: %w", err)
		}

		hmacKey, err := base64.RawURLEncoding.DecodeString(eabHMAC)
		if err != nil {
			return fmt.Errorf("failed to decode ZeroSSL HMAC key: %w", err)
		}

		acmeClient = &acme.Client{
			DirectoryURL: "https://acme.zerossl.com/v2/DV90",
		}
		eab = &acme.ExternalAccountBinding{
			KID: eabKID,
			Key: hmacKey,
		}
	} else {
		// Default: Let's Encrypt
		log.Printf("[tls] Using Let's Encrypt ACME directory")
		acmeClient = &acme.Client{
			DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		}
	}

	certManager := &autocert.Manager{
		Prompt:                 autocert.AcceptTOS,
		Cache:                  autocert.DirCache(s.config.AutoTLSDir),
		HostPolicy:             autocert.HostWhitelist(domain, wildcardDomain),
		Email:                  s.config.AutoTLSEmail,
		Client:                 acmeClient,
		ExternalAccountBinding: eab,
	}

	// Combined handler that routes based on Host header
	combinedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}
		// If the request is for a subdomain, route to proxy; otherwise admin
		if host != domain && strings.HasSuffix(host, "."+domain) {
			proxyHandler.ServeHTTP(w, r)
		} else {
			adminHandler.ServeHTTP(w, r)
		}
	})

	tlsConfig := &tls.Config{
		GetCertificate: certManager.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
	}

	// Start HTTP server for ACME challenges (port 80)
	go func() {
		log.Printf("[tls] HTTP challenge listener on :80")
		httpServer := &http.Server{
			Addr:    ":80",
			Handler: certManager.HTTPHandler(nil),
		}
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[tls] HTTP challenge server error: %v", err)
		}
	}()

	// Start HTTPS server (port 443)
	httpsServer := &http.Server{
		Addr:      ":443",
		Handler:   combinedHandler,
		TLSConfig: tlsConfig,
	}

	log.Printf("[tls] HTTPS server listening on :443")
	log.Printf("[admin] Dashboard: https://%s", domain)
	log.Printf("[proxy] Tunnels: https://*.%s", domain)
	fmt.Println()

	return httpsServer.ListenAndServeTLS("", "")
}

// getZeroSSLEAB fetches External Account Binding credentials from ZeroSSL API
func getZeroSSLEAB(apiKey string) (kid string, hmacKey string, err error) {
	resp, err := http.Post(
		"https://api.zerossl.com/acme/eab-credentials?access_key="+apiKey,
		"application/json",
		nil,
	)
	if err != nil {
		return "", "", fmt.Errorf("ZeroSSL EAB request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success    bool   `json:"success"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("failed to parse ZeroSSL response: %w", err)
	}
	if !result.Success {
		return "", "", fmt.Errorf("ZeroSSL returned unsuccessful response")
	}
	return result.EABKID, result.EABHMACKey, nil
}
