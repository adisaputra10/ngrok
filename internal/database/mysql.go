package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"gotunnel/internal/models"

	_ "github.com/go-sql-driver/mysql"
)

// MySQLDB wraps the MySQL database connection
type MySQLDB struct {
	conn *sql.DB
}

// NewMySQL creates a new MySQL database connection and initializes the schema
// dsn format: user:password@tcp(host:port)/dbname
func NewMySQL(dsn string) (DB, error) {
	// Add parseTime=true if not already present (required for time.Time scanning)
	if !strings.Contains(dsn, "parseTime") {
		if strings.Contains(dsn, "?") {
			dsn += "&parseTime=true"
		} else {
			dsn += "?parseTime=true"
		}
	}

	conn, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Test connection
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(time.Hour)

	db := &MySQLDB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	return db, nil
}

// Close closes the database connection
func (db *MySQLDB) Close() error {
	return db.conn.Close()
}

func (db *MySQLDB) migrate() error {
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS users (
			id BIGINT PRIMARY KEY AUTO_INCREMENT,
			email VARCHAR(255) UNIQUE NOT NULL,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			auth_token VARCHAR(255) UNIQUE NOT NULL,
			is_admin BOOLEAN DEFAULT FALSE,
			max_tunnels INT DEFAULT 5,
			max_uptime_monitors INT DEFAULT 3,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			INDEX idx_auth_token (auth_token)
		)`,
		`CREATE TABLE IF NOT EXISTS tunnels (
			id BIGINT PRIMARY KEY AUTO_INCREMENT,
			user_id BIGINT NOT NULL,
			subdomain VARCHAR(255) UNIQUE NOT NULL,
			status VARCHAR(50) DEFAULT 'offline',
			reserved BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_connected_at TIMESTAMP NULL,
			total_requests BIGINT DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			INDEX idx_user_id (user_id),
			INDEX idx_subdomain (subdomain)
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id VARCHAR(255) PRIMARY KEY,
			user_id BIGINT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			INDEX idx_user_id (user_id),
			INDEX idx_expires (expires_at)
		)`,
		`CREATE TABLE IF NOT EXISTS request_logs (
			id BIGINT PRIMARY KEY AUTO_INCREMENT,
			tunnel_id BIGINT NOT NULL,
			method VARCHAR(10) NOT NULL,
			path LONGTEXT NOT NULL,
			status_code INT DEFAULT 0,
			duration_ms FLOAT DEFAULT 0,
			remote_addr VARCHAR(45),
			user_agent LONGTEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (tunnel_id) REFERENCES tunnels(id) ON DELETE CASCADE,
			INDEX idx_tunnel_id (tunnel_id),
			INDEX idx_created (created_at)
		)`,
		`CREATE TABLE IF NOT EXISTS uptime_monitors (
			id BIGINT PRIMARY KEY AUTO_INCREMENT,
			user_id BIGINT NOT NULL,
			name VARCHAR(255) NOT NULL,
			url TEXT NOT NULL,
			check_type VARCHAR(50) NOT NULL DEFAULT 'http',
			interval_min INT NOT NULL DEFAULT 5,
			timeout_sec INT NOT NULL DEFAULT 10,
			expected_code INT NOT NULL DEFAULT 200,
			enabled BOOLEAN DEFAULT TRUE,
			status VARCHAR(50) DEFAULT 'unknown',
			last_checked_at TIMESTAMP NULL,
			last_latency_ms FLOAT DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			INDEX idx_user_id (user_id)
		)`,
		`CREATE TABLE IF NOT EXISTS uptime_logs (
			id BIGINT PRIMARY KEY AUTO_INCREMENT,
			monitor_id BIGINT NOT NULL,
			status VARCHAR(50) NOT NULL,
			latency_ms FLOAT DEFAULT 0,
			status_code INT DEFAULT 0,
			error TEXT DEFAULT '',
			checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (monitor_id) REFERENCES uptime_monitors(id) ON DELETE CASCADE,
			INDEX idx_monitor_id (monitor_id),
			INDEX idx_checked_at (checked_at)
		)`,
		`CREATE TABLE IF NOT EXISTS custom_domains (
			id BIGINT PRIMARY KEY AUTO_INCREMENT,
			tunnel_id BIGINT NOT NULL,
			user_id BIGINT NOT NULL,
			domain VARCHAR(253) UNIQUE NOT NULL,
			status VARCHAR(50) DEFAULT 'pending',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (tunnel_id) REFERENCES tunnels(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			INDEX idx_domain (domain),
			INDEX idx_tunnel_id (tunnel_id)
		)`,
		`ALTER TABLE users ADD COLUMN max_uptime_monitors INT DEFAULT 3`,
	} {
		if _, err := db.conn.Exec(stmt); err != nil {
			// Table might already exist, continue
		}
	}

	return nil
}

// --- User operations ---

func (db *MySQLDB) CreateUser(email, username, passwordHash, authToken string) (*models.User, error) {
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

func (db *MySQLDB) GetUserByID(id int64) (*models.User, error) {
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

func (db *MySQLDB) GetUserByEmail(email string) (*models.User, error) {
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

func (db *MySQLDB) GetUserByUsername(username string) (*models.User, error) {
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

func (db *MySQLDB) GetUserByAuthToken(token string) (*models.User, error) {
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

func (db *MySQLDB) UpdateUserToken(userID int64, newToken string) error {
	_, err := db.conn.Exec(
		`UPDATE users SET auth_token = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		newToken, userID,
	)
	return err
}

func (db *MySQLDB) UpdateUserPassword(userID int64, passwordHash string) error {
	_, err := db.conn.Exec(
		`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		passwordHash, userID,
	)
	return err
}

func (db *MySQLDB) UpdateUserAdmin(userID int64, isAdmin bool) error {
	_, err := db.conn.Exec(
		`UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		isAdmin, userID,
	)
	return err
}

func (db *MySQLDB) GetAllUsers() ([]*models.User, error) {
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

func (db *MySQLDB) UserCount() (int, error) {
	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

// UpdateUserMaxTunnels updates the max tunnels allowed for a user
func (db *MySQLDB) UpdateUserMaxTunnels(userID int64, maxTunnels int) error {
	_, err := db.conn.Exec(
		`UPDATE users SET max_tunnels = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		maxTunnels, userID,
	)
	return err
}

// UpdateUserMaxUptimeMonitors updates the max uptime monitors allowed for a user
func (db *MySQLDB) UpdateUserMaxUptimeMonitors(userID int64, max int) error {
	_, err := db.conn.Exec(
		`UPDATE users SET max_uptime_monitors = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		max, userID,
	)
	return err
}

// DeleteUser deletes a user and all their data (cascades to tunnels, sessions, logs)
func (db *MySQLDB) DeleteUser(id int64) error {
	_, err := db.conn.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

// --- Session operations ---

func (db *MySQLDB) CreateSession(id string, userID int64, expiresAt time.Time) error {
	_, err := db.conn.Exec(
		`INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)`,
		id, userID, expiresAt,
	)
	return err
}

func (db *MySQLDB) GetSession(id string) (*models.Session, error) {
	session := &models.Session{}
	err := db.conn.QueryRow(
		`SELECT id, user_id, expires_at, created_at FROM sessions WHERE id = ? AND expires_at > NOW()`,
		id,
	).Scan(&session.ID, &session.UserID, &session.ExpiresAt, &session.CreatedAt)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (db *MySQLDB) DeleteSession(id string) error {
	_, err := db.conn.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (db *MySQLDB) DeleteExpiredSessions() error {
	_, err := db.conn.Exec(`DELETE FROM sessions WHERE expires_at < NOW()`)
	return err
}

// --- Tunnel operations ---

func (db *MySQLDB) CreateTunnel(userID int64, subdomain string, reserved bool) (*models.Tunnel, error) {
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

func (db *MySQLDB) GetTunnelByID(id int64) (*models.Tunnel, error) {
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

func (db *MySQLDB) GetTunnelBySubdomain(subdomain string) (*models.Tunnel, error) {
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

func (db *MySQLDB) GetTunnelsByUserID(userID int64) ([]*models.Tunnel, error) {
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

func (db *MySQLDB) UpdateTunnelStatus(subdomain, status string) error {
	_, err := db.conn.Exec(
		`UPDATE tunnels SET status = ?, last_connected_at = NOW() WHERE subdomain = ?`,
		status, subdomain,
	)
	return err
}

func (db *MySQLDB) IncrementTunnelRequests(subdomain string) error {
	_, err := db.conn.Exec(
		`UPDATE tunnels SET total_requests = total_requests + 1 WHERE subdomain = ?`,
		subdomain,
	)
	return err
}

func (db *MySQLDB) DeleteTunnel(id int64, userID int64) error {
	_, err := db.conn.Exec(`DELETE FROM tunnels WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

// AdminDeleteTunnel deletes any tunnel by id (admin only, no user check)
func (db *MySQLDB) AdminDeleteTunnel(id int64) error {
	_, err := db.conn.Exec(`DELETE FROM tunnels WHERE id = ?`, id)
	return err
}

func (db *MySQLDB) GetAllTunnels() ([]*models.Tunnel, error) {
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

func (db *MySQLDB) LogRequest(tunnelID int64, method, path string, statusCode int, durationMs float64, remoteAddr, userAgent string) error {
	_, err := db.conn.Exec(
		`INSERT INTO request_logs (tunnel_id, method, path, status_code, duration_ms, remote_addr, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		tunnelID, method, path, statusCode, durationMs, remoteAddr, userAgent,
	)
	return err
}

func (db *MySQLDB) GetRecentLogs(tunnelID int64, limit int) ([]*models.RequestLog, error) {
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

func (db *MySQLDB) GetStats(userID int64) (*models.TunnelStats, error) {
	stats := &models.TunnelStats{}

	db.conn.QueryRow(
		`SELECT COALESCE(SUM(total_requests), 0) FROM tunnels WHERE user_id = ?`, userID,
	).Scan(&stats.TotalRequests)

	db.conn.QueryRow(
		`SELECT COUNT(*) FROM tunnels WHERE user_id = ?`, userID,
	).Scan(&stats.TotalTunnels)

	db.conn.QueryRow(
		`SELECT COUNT(*) FROM tunnels WHERE user_id = ? AND status = 'online'`, userID,
	).Scan(&stats.ActiveTunnels)

	db.conn.QueryRow(
		`SELECT COUNT(*) FROM request_logs rl 
		 JOIN tunnels t ON rl.tunnel_id = t.id 
		 WHERE t.user_id = ? AND rl.created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)`, userID,
	).Scan(&stats.RequestsToday)

	db.conn.QueryRow(
		`SELECT COALESCE(AVG(duration_ms), 0) FROM request_logs rl 
		 JOIN tunnels t ON rl.tunnel_id = t.id 
		 WHERE t.user_id = ? AND rl.created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)`, userID,
	).Scan(&stats.AvgResponseTime)

	return stats, nil
}

func (db *MySQLDB) CleanupOldLogs(days int) error {
	_, err := db.conn.Exec(
		`DELETE FROM request_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)`,
		days,
	)
	return err
}

// --- Uptime monitor operations ---

func (db *MySQLDB) CreateUptimeMonitor(userID int64, name, url, checkType string, intervalMin, timeoutSec, expectedCode int) (*models.UptimeMonitor, error) {
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

func (db *MySQLDB) GetUptimeMonitorByID(id int64) (*models.UptimeMonitor, error) {
	m := &models.UptimeMonitor{}
	err := db.conn.QueryRow(
		`SELECT id, user_id, name, url, check_type, interval_min, timeout_sec, expected_code, enabled, status, last_checked_at, last_latency_ms, created_at FROM uptime_monitors WHERE id = ?`, id,
	).Scan(&m.ID, &m.UserID, &m.Name, &m.URL, &m.CheckType, &m.IntervalMin, &m.TimeoutSec, &m.ExpectedCode, &m.Enabled, &m.Status, &m.LastCheckedAt, &m.LastLatencyMs, &m.CreatedAt)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (db *MySQLDB) GetUptimeMonitorsByUserID(userID int64) ([]*models.UptimeMonitor, error) {
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

func (db *MySQLDB) GetAllUptimeMonitors() ([]*models.UptimeMonitor, error) {
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

func (db *MySQLDB) UpdateUptimeMonitorStatus(id int64, status string, latencyMs float64, checkedAt time.Time) error {
	_, err := db.conn.Exec(
		`UPDATE uptime_monitors SET status = ?, last_latency_ms = ?, last_checked_at = ? WHERE id = ?`,
		status, latencyMs, checkedAt, id,
	)
	return err
}

func (db *MySQLDB) DeleteUptimeMonitor(id int64, userID int64) error {
	_, err := db.conn.Exec(`DELETE FROM uptime_monitors WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

func (db *MySQLDB) LogUptimeCheck(monitorID int64, status string, latencyMs float64, statusCode int, errMsg string) error {
	_, err := db.conn.Exec(
		`INSERT INTO uptime_logs (monitor_id, status, latency_ms, status_code, error) VALUES (?, ?, ?, ?, ?)`,
		monitorID, status, latencyMs, statusCode, errMsg,
	)
	return err
}

func (db *MySQLDB) GetUptimeLogs(monitorID int64, limit int) ([]*models.UptimeLog, error) {
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

func (db *MySQLDB) GetUptimePct(monitorID int64, hours int) (float64, error) {
	var total, up int
	db.conn.QueryRow(
		`SELECT COUNT(*) FROM uptime_logs WHERE monitor_id = ? AND checked_at > DATE_SUB(NOW(), INTERVAL ? HOUR)`,
		monitorID, hours,
	).Scan(&total)
	if total == 0 {
		return 100.0, nil
	}
	db.conn.QueryRow(
		`SELECT COUNT(*) FROM uptime_logs WHERE monitor_id = ? AND status = 'up' AND checked_at > DATE_SUB(NOW(), INTERVAL ? HOUR)`,
		monitorID, hours,
	).Scan(&up)
	return float64(up) / float64(total) * 100, nil
}

// --- Custom Domain operations ---

func (db *MySQLDB) CreateCustomDomain(userID, tunnelID int64, domain string) (*models.CustomDomain, error) {
	result, err := db.conn.Exec(
		`INSERT INTO custom_domains (tunnel_id, user_id, domain) VALUES (?, ?, ?)`,
		tunnelID, userID, domain,
	)
	if err != nil {
		return nil, err
	}
	id, _ := result.LastInsertId()
	cd := &models.CustomDomain{}
	err = db.conn.QueryRow(
		`SELECT id, tunnel_id, user_id, domain, status, created_at FROM custom_domains WHERE id = ?`, id,
	).Scan(&cd.ID, &cd.TunnelID, &cd.UserID, &cd.Domain, &cd.Status, &cd.CreatedAt)
	return cd, err
}

func (db *MySQLDB) GetCustomDomainsByTunnelID(tunnelID int64) ([]*models.CustomDomain, error) {
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

func (db *MySQLDB) GetCustomDomainsByUserID(userID int64) ([]*models.CustomDomain, error) {
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

func (db *MySQLDB) GetCustomDomainByDomain(domain string) (*models.CustomDomain, error) {
	cd := &models.CustomDomain{}
	err := db.conn.QueryRow(
		`SELECT id, tunnel_id, user_id, domain, status, created_at FROM custom_domains WHERE domain = ?`, domain,
	).Scan(&cd.ID, &cd.TunnelID, &cd.UserID, &cd.Domain, &cd.Status, &cd.CreatedAt)
	if err != nil {
		return nil, err
	}
	return cd, nil
}

func (db *MySQLDB) UpdateCustomDomainStatus(id int64, status string) error {
	_, err := db.conn.Exec(`UPDATE custom_domains SET status = ? WHERE id = ?`, status, id)
	return err
}

func (db *MySQLDB) DeleteCustomDomain(id int64, userID int64) error {
	_, err := db.conn.Exec(`DELETE FROM custom_domains WHERE id = ? AND user_id = ?`, id, userID)
	return err
}
