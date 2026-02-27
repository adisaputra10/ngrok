package models

import "time"

// User represents a registered user
type User struct {
	ID           int64     `json:"id"`
	Email        string    `json:"email"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	AuthToken    string    `json:"auth_token"`
	IsAdmin      bool      `json:"is_admin"`
	MaxTunnels   int       `json:"max_tunnels"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Tunnel represents a tunnel configuration
type Tunnel struct {
	ID              int64      `json:"id"`
	UserID          int64      `json:"user_id"`
	Subdomain       string     `json:"subdomain"`
	LocalPort       int        `json:"local_port,omitempty"`
	Status          string     `json:"status"` // online, offline
	Reserved        bool       `json:"reserved"`
	CreatedAt       time.Time  `json:"created_at"`
	LastConnectedAt *time.Time `json:"last_connected_at,omitempty"`
	TotalRequests   int64      `json:"total_requests"`
	Username        string     `json:"username,omitempty"` // joined field
}

// Session represents a user login session
type Session struct {
	ID        string    `json:"id"`
	UserID    int64     `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// RequestLog represents a logged HTTP request through the tunnel
type RequestLog struct {
	ID         int64     `json:"id"`
	TunnelID   int64     `json:"tunnel_id"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	StatusCode int       `json:"status_code"`
	DurationMs float64   `json:"duration_ms"`
	RemoteAddr string    `json:"remote_addr"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
}

// TunnelStats represents aggregated tunnel statistics
type TunnelStats struct {
	TotalRequests   int64   `json:"total_requests"`
	ActiveTunnels   int     `json:"active_tunnels"`
	TotalTunnels    int     `json:"total_tunnels"`
	AvgResponseTime float64 `json:"avg_response_time_ms"`
	RequestsToday   int64   `json:"requests_today"`
}

// ConnectionInfo represents a live tunnel connection
type ConnectionInfo struct {
	TunnelID    string    `json:"tunnel_id"`
	Subdomain   string    `json:"subdomain"`
	URL         string    `json:"url"`
	LocalPort   int       `json:"local_port"`
	ConnectedAt time.Time `json:"connected_at"`
	Requests    int64     `json:"requests"`
	UserID      int64     `json:"user_id"`
	Username    string    `json:"username"`
}
