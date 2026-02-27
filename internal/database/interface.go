package database

import (
	"time"

	"gotunnel/internal/models"
)

// DB adalah interface untuk semua database operations
type DB interface {
	// User operations
	CreateUser(email, username, passwordHash, authToken string) (*models.User, error)
	GetUserByID(id int64) (*models.User, error)
	GetUserByEmail(email string) (*models.User, error)
	GetUserByUsername(username string) (*models.User, error)
	GetUserByAuthToken(token string) (*models.User, error)
	UpdateUserToken(userID int64, newToken string) error
	UpdateUserPassword(userID int64, passwordHash string) error
	UpdateUserAdmin(userID int64, isAdmin bool) error
	UpdateUserMaxTunnels(userID int64, maxTunnels int) error
	DeleteUser(id int64) error
	GetAllUsers() ([]*models.User, error)
	UserCount() (int, error)

	// Session operations
	CreateSession(id string, userID int64, expiresAt time.Time) error
	GetSession(id string) (*models.Session, error)
	DeleteSession(id string) error
	DeleteExpiredSessions() error

	// Tunnel operations
	CreateTunnel(userID int64, subdomain string, reserved bool) (*models.Tunnel, error)
	GetTunnelByID(id int64) (*models.Tunnel, error)
	GetTunnelBySubdomain(subdomain string) (*models.Tunnel, error)
	GetTunnelsByUserID(userID int64) ([]*models.Tunnel, error)
	UpdateTunnelStatus(subdomain, status string) error
	IncrementTunnelRequests(subdomain string) error
	DeleteTunnel(id int64, userID int64) error
	GetAllTunnels() ([]*models.Tunnel, error)

	// Request log operations
	LogRequest(tunnelID int64, method, path string, statusCode int, durationMs float64, remoteAddr, userAgent string) error
	GetRecentLogs(tunnelID int64, limit int) ([]*models.RequestLog, error)
	GetStats(userID int64) (*models.TunnelStats, error)
	CleanupOldLogs(days int) error

	// Connection management
	Close() error
}
