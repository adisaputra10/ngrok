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
		max_uptime_monitors INTEGER DEFAULT 3,
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

	CREATE TABLE IF NOT EXISTS uptime_monitors (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		check_type TEXT NOT NULL DEFAULT 'http',
		interval_min INTEGER NOT NULL DEFAULT 5,
		timeout_sec INTEGER NOT NULL DEFAULT 10,
		expected_code INTEGER NOT NULL DEFAULT 200,
		enabled BOOLEAN DEFAULT TRUE,
		status TEXT DEFAULT 'unknown',
		last_checked_at DATETIME,
		last_latency_ms REAL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS uptime_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		monitor_id INTEGER NOT NULL,
		status TEXT NOT NULL,
		latency_ms REAL DEFAULT 0,
		status_code INTEGER DEFAULT 0,
		error TEXT DEFAULT '',
		checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (monitor_id) REFERENCES uptime_monitors(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_uptime_monitors_user_id ON uptime_monitors(user_id);
	CREATE INDEX IF NOT EXISTS idx_uptime_logs_monitor_id ON uptime_logs(monitor_id);
	CREATE INDEX IF NOT EXISTS idx_uptime_logs_checked_at ON uptime_logs(checked_at);

	CREATE TABLE IF NOT EXISTS custom_domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tunnel_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		domain TEXT UNIQUE NOT NULL,
		status TEXT DEFAULT 'pending',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (tunnel_id) REFERENCES tunnels(id) ON DELETE CASCADE,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_custom_domains_domain ON custom_domains(domain);
	CREATE INDEX IF NOT EXISTS idx_custom_domains_tunnel ON custom_domains(tunnel_id);
	`

	_, err := db.conn.Exec(schema)
	if err != nil {
		return err
	}
	// Add columns for existing databases (error ignored if already present)
	db.conn.Exec(`ALTER TABLE users ADD COLUMN max_uptime_monitors INTEGER DEFAULT 3`)
	return nil
}

// --- Custom Domain operations ---

func (db *SQLiteDB) CreateCustomDomain(userID, tunnelID int64, domain string) (*models.CustomDomain, error) {
	result, err := db.conn.Exec(
		`INSERT INTO custom_domains (tunnel_id, user_id, domain) VALUES (?, ?, ?)`,
		tunnelID, userID, domain,
	)
	if err != nil {
		return nil, err
	}
	id, _ := result.LastInsertId()
	return db.getCustomDomainByID(id)
}

func (db *SQLiteDB) getCustomDomainByID(id int64) (*models.CustomDomain, error) {
	cd := &models.CustomDomain{}
	err := db.conn.QueryRow(
		`SELECT id, tunnel_id, user_id, domain, status, created_at FROM custom_domains WHERE id = ?`, id,
	).Scan(&cd.ID, &cd.TunnelID, &cd.UserID, &cd.Domain, &cd.Status, &cd.CreatedAt)
	if err != nil {
		return nil, err
	}
	return cd, nil
}

func (db *SQLiteDB) GetCustomDomainsByTunnelID(tunnelID int64) ([]*models.CustomDomain, error) {
	rows, err := db.conn.Query(
		`SELECT id, tunnel_id, user_id, domain, status, created_at FROM custom_domains WHERE tunnel_id = ? ORDER BY created_at DESC`,
		tunnelID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*models.CustomDomain
	for rows.Next() {
		cd := &models.CustomDomain{}
		if err := rows.Scan(&cd.ID, &cd.TunnelID, &cd.UserID, &cd.Domain, &cd.Status, &cd.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, cd)
	}
	return list, nil
}

func (db *SQLiteDB) GetCustomDomainsByUserID(userID int64) ([]*models.CustomDomain, error) {
	rows, err := db.conn.Query(
		`SELECT id, tunnel_id, user_id, domain, status, created_at FROM custom_domains WHERE user_id = ? ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*models.CustomDomain
	for rows.Next() {
		cd := &models.CustomDomain{}
		if err := rows.Scan(&cd.ID, &cd.TunnelID, &cd.UserID, &cd.Domain, &cd.Status, &cd.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, cd)
	}
	return list, nil
}

func (db *SQLiteDB) GetCustomDomainByDomain(domain string) (*models.CustomDomain, error) {
	cd := &models.CustomDomain{}
	err := db.conn.QueryRow(
		`SELECT id, tunnel_id, user_id, domain, status, created_at FROM custom_domains WHERE domain = ?`, domain,
	).Scan(&cd.ID, &cd.TunnelID, &cd.UserID, &cd.Domain, &cd.Status, &cd.CreatedAt)
	if err != nil {
		return nil, err
	}
	return cd, nil
}

func (db *SQLiteDB) UpdateCustomDomainStatus(id int64, status string) error {
	_, err := db.conn.Exec(`UPDATE custom_domains SET status = ? WHERE id = ?`, status, id)
	return err
}

func (db *SQLiteDB) DeleteCustomDomain(id int64, userID int64) error {
	_, err := db.conn.Exec(`DELETE FROM custom_domains WHERE id = ? AND user_id = ?`, id, userID)
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
		`SELECT id, email, username, password_hash, auth_token, is_admin, max_tunnels, max_uptime_monitors, created_at, updated_at FROM users WHERE id = ?`,
		id,
	).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.AuthToken, &user.IsAdmin, &user.MaxTunnels, &user.MaxUptimeMonitors, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByEmail retrieves a user by email
func (db *SQLiteDB) GetUserByEmail(email string) (*models.User, error) {
	user := &models.User{}
	err := db.conn.QueryRow(
		`SELECT id, email, username, password_hash, auth_token, is_admin, max_tunnels, max_uptime_monitors, created_at, updated_at FROM users WHERE email = ?`,
		email,
	).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.AuthToken, &user.IsAdmin, &user.MaxTunnels, &user.MaxUptimeMonitors, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByUsername retrieves a user by username
func (db *SQLiteDB) GetUserByUsername(username string) (*models.User, error) {
	user := &models.User{}
	err := db.conn.QueryRow(
		`SELECT id, email, username, password_hash, auth_token, is_admin, max_tunnels, max_uptime_monitors, created_at, updated_at FROM users WHERE username = ?`,
		username,
	).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.AuthToken, &user.IsAdmin, &user.MaxTunnels, &user.MaxUptimeMonitors, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByAuthToken retrieves a user by auth token
func (db *SQLiteDB) GetUserByAuthToken(token string) (*models.User, error) {
	user := &models.User{}
	err := db.conn.QueryRow(
		`SELECT id, email, username, password_hash, auth_token, is_admin, max_tunnels, max_uptime_monitors, created_at, updated_at FROM users WHERE auth_token = ?`,
		token,
	).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.AuthToken, &user.IsAdmin, &user.MaxTunnels, &user.MaxUptimeMonitors, &user.CreatedAt, &user.UpdatedAt)
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
		`SELECT id, email, username, password_hash, auth_token, is_admin, max_tunnels, max_uptime_monitors, created_at, updated_at FROM users ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.AuthToken, &user.IsAdmin, &user.MaxTunnels, &user.MaxUptimeMonitors, &user.CreatedAt, &user.UpdatedAt)
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

// UpdateUserMaxUptimeMonitors updates the max uptime monitors allowed for a user
func (db *SQLiteDB) UpdateUserMaxUptimeMonitors(userID int64, max int) error {
	_, err := db.conn.Exec(
		`UPDATE users SET max_uptime_monitors = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		max, userID,
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
// --- Uptime monitor operations ---

func (db *SQLiteDB) CreateUptimeMonitor(userID int64, name, url, checkType string, intervalMin, timeoutSec, expectedCode int) (*models.UptimeMonitor, error) {
	result, err := db.conn.Exec(
		`INSERT INTO uptime_monitors (user_id, name, url, check_type, interval_min, timeout_sec, expected_code) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, name, url, checkType, intervalMin, timeoutSec, expectedCode,
	)
	if err != nil {
		return nil, err
	}
	id, _ := result.LastInsertId()
	return db.GetUptimeMonitorByID(id)
}

func (db *SQLiteDB) GetUptimeMonitorByID(id int64) (*models.UptimeMonitor, error) {
	m := &models.UptimeMonitor{}
	err := db.conn.QueryRow(
		`SELECT id, user_id, name, url, check_type, interval_min, timeout_sec, expected_code, enabled, status, last_checked_at, last_latency_ms, created_at FROM uptime_monitors WHERE id = ?`, id,
	).Scan(&m.ID, &m.UserID, &m.Name, &m.URL, &m.CheckType, &m.IntervalMin, &m.TimeoutSec, &m.ExpectedCode, &m.Enabled, &m.Status, &m.LastCheckedAt, &m.LastLatencyMs, &m.CreatedAt)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (db *SQLiteDB) GetUptimeMonitorsByUserID(userID int64) ([]*models.UptimeMonitor, error) {
	rows, err := db.conn.Query(
		`SELECT id, user_id, name, url, check_type, interval_min, timeout_sec, expected_code, enabled, status, last_checked_at, last_latency_ms, created_at FROM uptime_monitors WHERE user_id = ? ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var monitors []*models.UptimeMonitor
	for rows.Next() {
		m := &models.UptimeMonitor{}
		if err := rows.Scan(&m.ID, &m.UserID, &m.Name, &m.URL, &m.CheckType, &m.IntervalMin, &m.TimeoutSec, &m.ExpectedCode, &m.Enabled, &m.Status, &m.LastCheckedAt, &m.LastLatencyMs, &m.CreatedAt); err != nil {
			return nil, err
		}
		monitors = append(monitors, m)
	}
	return monitors, nil
}

func (db *SQLiteDB) GetAllUptimeMonitors() ([]*models.UptimeMonitor, error) {
	rows, err := db.conn.Query(
		`SELECT id, user_id, name, url, check_type, interval_min, timeout_sec, expected_code, enabled, status, last_checked_at, last_latency_ms, created_at FROM uptime_monitors WHERE enabled = TRUE ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var monitors []*models.UptimeMonitor
	for rows.Next() {
		m := &models.UptimeMonitor{}
		if err := rows.Scan(&m.ID, &m.UserID, &m.Name, &m.URL, &m.CheckType, &m.IntervalMin, &m.TimeoutSec, &m.ExpectedCode, &m.Enabled, &m.Status, &m.LastCheckedAt, &m.LastLatencyMs, &m.CreatedAt); err != nil {
			return nil, err
		}
		monitors = append(monitors, m)
	}
	return monitors, nil
}

func (db *SQLiteDB) UpdateUptimeMonitorStatus(id int64, status string, latencyMs float64, checkedAt time.Time) error {
	_, err := db.conn.Exec(
		`UPDATE uptime_monitors SET status = ?, last_latency_ms = ?, last_checked_at = ? WHERE id = ?`,
		status, latencyMs, checkedAt, id,
	)
	return err
}

func (db *SQLiteDB) DeleteUptimeMonitor(id int64, userID int64) error {
	_, err := db.conn.Exec(`DELETE FROM uptime_monitors WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

func (db *SQLiteDB) LogUptimeCheck(monitorID int64, status string, latencyMs float64, statusCode int, errMsg string) error {
	_, err := db.conn.Exec(
		`INSERT INTO uptime_logs (monitor_id, status, latency_ms, status_code, error) VALUES (?, ?, ?, ?, ?)`,
		monitorID, status, latencyMs, statusCode, errMsg,
	)
	return err
}

func (db *SQLiteDB) GetUptimeLogs(monitorID int64, limit int) ([]*models.UptimeLog, error) {
	rows, err := db.conn.Query(
		`SELECT id, monitor_id, status, latency_ms, status_code, error, checked_at FROM uptime_logs WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT ?`,
		monitorID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []*models.UptimeLog
	for rows.Next() {
		l := &models.UptimeLog{}
		if err := rows.Scan(&l.ID, &l.MonitorID, &l.Status, &l.LatencyMs, &l.StatusCode, &l.Error, &l.CheckedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

func (db *SQLiteDB) GetUptimePct(monitorID int64, hours int) (float64, error) {
	var total, up int
	db.conn.QueryRow(
		`SELECT COUNT(*) FROM uptime_logs WHERE monitor_id = ? AND checked_at > datetime('now', ? || ' hours')`,
		monitorID, fmt.Sprintf("-%d", hours),
	).Scan(&total)
	if total == 0 {
		return 100.0, nil
	}
	db.conn.QueryRow(
		`SELECT COUNT(*) FROM uptime_logs WHERE monitor_id = ? AND status = 'up' AND checked_at > datetime('now', ? || ' hours')`,
		monitorID, fmt.Sprintf("-%d", hours),
	).Scan(&up)
	return float64(up) / float64(total) * 100, nil
}