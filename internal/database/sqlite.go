package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gotunnel/internal/models"

	_ "modernc.org/sqlite"
)

// SQLiteDB wraps the SQLite database connection
type SQLiteDB struct {
	conn *sql.DB
}

// NewSQLite creates a new SQLite database connection and initializes the schema
func NewSQLite(dbPath string) (DB, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	conn, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	conn.SetMaxOpenConns(1) // SQLite only supports one writer
	conn.SetMaxIdleConns(2)
	conn.SetConnMaxLifetime(time.Hour)

	db := &SQLiteDB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	return db, nil
}

// Close closes the database connection
func (db *SQLiteDB) Close() error {
	return db.conn.Close()
}

func (db *SQLiteDB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		auth_token TEXT UNIQUE NOT NULL,
		is_admin BOOLEAN DEFAULT FALSE,
		max_tunnels INTEGER DEFAULT 5,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS tunnels (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		subdomain TEXT UNIQUE NOT NULL,
		status TEXT DEFAULT 'offline',
		reserved BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_connected_at DATETIME,
		total_requests INTEGER DEFAULT 0,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS request_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tunnel_id INTEGER NOT NULL,
		method TEXT NOT NULL,
		path TEXT NOT NULL,
		status_code INTEGER DEFAULT 0,
		duration_ms REAL DEFAULT 0,
		remote_addr TEXT DEFAULT '',
		user_agent TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (tunnel_id) REFERENCES tunnels(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_tunnels_user_id ON tunnels(user_id);
	CREATE INDEX IF NOT EXISTS idx_tunnels_subdomain ON tunnels(subdomain);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_request_logs_tunnel_id ON request_logs(tunnel_id);
	CREATE INDEX IF NOT EXISTS idx_request_logs_created ON request_logs(created_at);
	`

	_, err := db.conn.Exec(schema)
	return err
}

// --- User operations ---

// CreateUser creates a new user
func (db *SQLiteDB) CreateUser(email, username, passwordHash, authToken string) (*models.User, error) {
	result, err := db.conn.Exec(
		`INSERT INTO users (email, username, password_hash, auth_token) VALUES (?, ?, ?, ?)`,
		email, username, passwordHash, authToken,
	)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()
	return db.GetUserByID(id)
}

// GetUserByID retrieves a user by ID
func (db *SQLiteDB) GetUserByID(id int64) (*models.User, error) {
	user := &models.User{}
	err := db.conn.QueryRow(
		`SELECT id, email, username, password_hash, auth_token, is_admin, max_tunnels, created_at, updated_at FROM users WHERE id = ?`,
		id,
	).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.AuthToken, &user.IsAdmin, &user.MaxTunnels, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByEmail retrieves a user by email
func (db *SQLiteDB) GetUserByEmail(email string) (*models.User, error) {
	user := &models.User{}
	err := db.conn.QueryRow(
		`SELECT id, email, username, password_hash, auth_token, is_admin, max_tunnels, created_at, updated_at FROM users WHERE email = ?`,
		email,
	).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.AuthToken, &user.IsAdmin, &user.MaxTunnels, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByUsername retrieves a user by username
func (db *SQLiteDB) GetUserByUsername(username string) (*models.User, error) {
	user := &models.User{}
	err := db.conn.QueryRow(
		`SELECT id, email, username, password_hash, auth_token, is_admin, max_tunnels, created_at, updated_at FROM users WHERE username = ?`,
		username,
	).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.AuthToken, &user.IsAdmin, &user.MaxTunnels, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByAuthToken retrieves a user by auth token
func (db *SQLiteDB) GetUserByAuthToken(token string) (*models.User, error) {
	user := &models.User{}
	err := db.conn.QueryRow(
		`SELECT id, email, username, password_hash, auth_token, is_admin, max_tunnels, created_at, updated_at FROM users WHERE auth_token = ?`,
		token,
	).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.AuthToken, &user.IsAdmin, &user.MaxTunnels, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// UpdateUserToken updates a user's auth token
func (db *SQLiteDB) UpdateUserToken(userID int64, newToken string) error {
	_, err := db.conn.Exec(
		`UPDATE users SET auth_token = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		newToken, userID,
	)
	return err
}

// UpdateUserPassword updates a user's password
func (db *SQLiteDB) UpdateUserPassword(userID int64, passwordHash string) error {
	_, err := db.conn.Exec(
		`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		passwordHash, userID,
	)
	return err
}

// UpdateUserAdmin sets a user's admin status
func (db *SQLiteDB) UpdateUserAdmin(userID int64, isAdmin bool) error {
	_, err := db.conn.Exec(
		`UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		isAdmin, userID,
	)
	return err
}

// GetAllUsers returns all users (for admin)
func (db *SQLiteDB) GetAllUsers() ([]*models.User, error) {
	rows, err := db.conn.Query(
		`SELECT id, email, username, password_hash, auth_token, is_admin, max_tunnels, created_at, updated_at FROM users ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.AuthToken, &user.IsAdmin, &user.MaxTunnels, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// UserCount returns the total number of users
func (db *SQLiteDB) UserCount() (int, error) {
	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

// UpdateUserMaxTunnels updates the max tunnels allowed for a user
func (db *SQLiteDB) UpdateUserMaxTunnels(userID int64, maxTunnels int) error {
	_, err := db.conn.Exec(
		`UPDATE users SET max_tunnels = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		maxTunnels, userID,
	)
	return err
}

// DeleteUser deletes a user and all their data (cascades to tunnels, sessions, logs)
func (db *SQLiteDB) DeleteUser(id int64) error {
	_, err := db.conn.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

// --- Session operations ---

// CreateSession creates a new session
func (db *SQLiteDB) CreateSession(id string, userID int64, expiresAt time.Time) error {
	_, err := db.conn.Exec(
		`INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)`,
		id, userID, expiresAt,
	)
	return err
}

// GetSession retrieves a session by ID
func (db *SQLiteDB) GetSession(id string) (*models.Session, error) {
	session := &models.Session{}
	err := db.conn.QueryRow(
		`SELECT id, user_id, expires_at, created_at FROM sessions WHERE id = ? AND expires_at > ?`,
		id, time.Now(),
	).Scan(&session.ID, &session.UserID, &session.ExpiresAt, &session.CreatedAt)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// DeleteSession removes a session
func (db *SQLiteDB) DeleteSession(id string) error {
	_, err := db.conn.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteExpiredSessions removes expired sessions
func (db *SQLiteDB) DeleteExpiredSessions() error {
	_, err := db.conn.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now())
	return err
}

// --- Tunnel operations ---

// CreateTunnel creates a new tunnel record
func (db *SQLiteDB) CreateTunnel(userID int64, subdomain string, reserved bool) (*models.Tunnel, error) {
	result, err := db.conn.Exec(
		`INSERT INTO tunnels (user_id, subdomain, reserved) VALUES (?, ?, ?)`,
		userID, subdomain, reserved,
	)
	if err != nil {
		return nil, err
	}
	id, _ := result.LastInsertId()
	return db.GetTunnelByID(id)
}

// GetTunnelByID retrieves a tunnel by ID
func (db *SQLiteDB) GetTunnelByID(id int64) (*models.Tunnel, error) {
	t := &models.Tunnel{}
	err := db.conn.QueryRow(
		`SELECT t.id, t.user_id, t.subdomain, t.status, t.reserved, t.created_at, t.last_connected_at, t.total_requests, COALESCE(u.username, '') 
		 FROM tunnels t LEFT JOIN users u ON t.user_id = u.id WHERE t.id = ?`,
		id,
	).Scan(&t.ID, &t.UserID, &t.Subdomain, &t.Status, &t.Reserved, &t.CreatedAt, &t.LastConnectedAt, &t.TotalRequests, &t.Username)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// GetTunnelBySubdomain retrieves a tunnel by subdomain
func (db *SQLiteDB) GetTunnelBySubdomain(subdomain string) (*models.Tunnel, error) {
	t := &models.Tunnel{}
	err := db.conn.QueryRow(
		`SELECT t.id, t.user_id, t.subdomain, t.status, t.reserved, t.created_at, t.last_connected_at, t.total_requests, COALESCE(u.username, '') 
		 FROM tunnels t LEFT JOIN users u ON t.user_id = u.id WHERE t.subdomain = ?`,
		subdomain,
	).Scan(&t.ID, &t.UserID, &t.Subdomain, &t.Status, &t.Reserved, &t.CreatedAt, &t.LastConnectedAt, &t.TotalRequests, &t.Username)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// GetTunnelsByUserID retrieves all tunnels for a user
func (db *SQLiteDB) GetTunnelsByUserID(userID int64) ([]*models.Tunnel, error) {
	rows, err := db.conn.Query(
		`SELECT t.id, t.user_id, t.subdomain, t.status, t.reserved, t.created_at, t.last_connected_at, t.total_requests, COALESCE(u.username, '')
		 FROM tunnels t LEFT JOIN users u ON t.user_id = u.id WHERE t.user_id = ? ORDER BY t.created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tunnels []*models.Tunnel
	for rows.Next() {
		t := &models.Tunnel{}
		err := rows.Scan(&t.ID, &t.UserID, &t.Subdomain, &t.Status, &t.Reserved, &t.CreatedAt, &t.LastConnectedAt, &t.TotalRequests, &t.Username)
		if err != nil {
			return nil, err
		}
		tunnels = append(tunnels, t)
	}
	return tunnels, nil
}

// UpdateTunnelStatus updates a tunnel's status
func (db *SQLiteDB) UpdateTunnelStatus(subdomain, status string) error {
	now := time.Now()
	_, err := db.conn.Exec(
		`UPDATE tunnels SET status = ?, last_connected_at = ? WHERE subdomain = ?`,
		status, now, subdomain,
	)
	return err
}

// IncrementTunnelRequests increments the request count for a tunnel
func (db *SQLiteDB) IncrementTunnelRequests(subdomain string) error {
	_, err := db.conn.Exec(
		`UPDATE tunnels SET total_requests = total_requests + 1 WHERE subdomain = ?`,
		subdomain,
	)
	return err
}

// DeleteTunnel deletes a tunnel
func (db *SQLiteDB) DeleteTunnel(id int64, userID int64) error {
	_, err := db.conn.Exec(`DELETE FROM tunnels WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

// GetAllTunnels returns all tunnels (for admin)
func (db *SQLiteDB) GetAllTunnels() ([]*models.Tunnel, error) {
	rows, err := db.conn.Query(
		`SELECT t.id, t.user_id, t.subdomain, t.status, t.reserved, t.created_at, t.last_connected_at, t.total_requests, COALESCE(u.username, '')
		 FROM tunnels t LEFT JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tunnels []*models.Tunnel
	for rows.Next() {
		t := &models.Tunnel{}
		err := rows.Scan(&t.ID, &t.UserID, &t.Subdomain, &t.Status, &t.Reserved, &t.CreatedAt, &t.LastConnectedAt, &t.TotalRequests, &t.Username)
		if err != nil {
			return nil, err
		}
		tunnels = append(tunnels, t)
	}
	return tunnels, nil
}

// --- Request log operations ---

// LogRequest logs an HTTP request
func (db *SQLiteDB) LogRequest(tunnelID int64, method, path string, statusCode int, durationMs float64, remoteAddr, userAgent string) error {
	_, err := db.conn.Exec(
		`INSERT INTO request_logs (tunnel_id, method, path, status_code, duration_ms, remote_addr, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		tunnelID, method, path, statusCode, durationMs, remoteAddr, userAgent,
	)
	return err
}

// GetRecentLogs retrieves recent request logs for a tunnel
func (db *SQLiteDB) GetRecentLogs(tunnelID int64, limit int) ([]*models.RequestLog, error) {
	rows, err := db.conn.Query(
		`SELECT id, tunnel_id, method, path, status_code, duration_ms, remote_addr, user_agent, created_at 
		 FROM request_logs WHERE tunnel_id = ? ORDER BY created_at DESC LIMIT ?`,
		tunnelID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*models.RequestLog
	for rows.Next() {
		l := &models.RequestLog{}
		err := rows.Scan(&l.ID, &l.TunnelID, &l.Method, &l.Path, &l.StatusCode, &l.DurationMs, &l.RemoteAddr, &l.UserAgent, &l.CreatedAt)
		if err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// GetStats returns aggregated statistics
func (db *SQLiteDB) GetStats(userID int64) (*models.TunnelStats, error) {
	stats := &models.TunnelStats{}

	// Total requests for this user's tunnels
	db.conn.QueryRow(
		`SELECT COALESCE(SUM(total_requests), 0) FROM tunnels WHERE user_id = ?`, userID,
	).Scan(&stats.TotalRequests)

	// Total tunnels
	db.conn.QueryRow(
		`SELECT COUNT(*) FROM tunnels WHERE user_id = ?`, userID,
	).Scan(&stats.TotalTunnels)

	// Active tunnels
	db.conn.QueryRow(
		`SELECT COUNT(*) FROM tunnels WHERE user_id = ? AND status = 'online'`, userID,
	).Scan(&stats.ActiveTunnels)

	// Today's requests
	db.conn.QueryRow(
		`SELECT COUNT(*) FROM request_logs rl 
		 JOIN tunnels t ON rl.tunnel_id = t.id 
		 WHERE t.user_id = ? AND rl.created_at > datetime('now', '-1 day')`, userID,
	).Scan(&stats.RequestsToday)

	// Average response time
	db.conn.QueryRow(
		`SELECT COALESCE(AVG(duration_ms), 0) FROM request_logs rl 
		 JOIN tunnels t ON rl.tunnel_id = t.id 
		 WHERE t.user_id = ? AND rl.created_at > datetime('now', '-1 hour')`, userID,
	).Scan(&stats.AvgResponseTime)

	return stats, nil
}

// CleanupOldLogs removes request logs older than the specified days
func (db *SQLiteDB) CleanupOldLogs(days int) error {
	_, err := db.conn.Exec(
		`DELETE FROM request_logs WHERE created_at < datetime('now', ? || ' days')`,
		fmt.Sprintf("-%d", days),
	)
	return err
}
