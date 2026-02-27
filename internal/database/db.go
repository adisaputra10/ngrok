package database

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// New creates a new database connection based on type from environment
// GOTUNNEL_DB_TYPE: "sqlite" (default) or "mysql"
// GOTUNNEL_SQLITE_DB_PATH: path to SQLite file (default: ./data/gotunnel.db)
// GOTUNNEL_MYSQL_DSN: MySQL DSN, format: user:password@tcp(host:port)/dbname
func New() (DB, error) {
	dbType := strings.ToLower(os.Getenv("GOTUNNEL_DB_TYPE"))
	if dbType == "" {
		dbType = "sqlite"
	}

	switch dbType {
	case "mysql":
		dsn := os.Getenv("GOTUNNEL_MYSQL_DSN")
		if dsn == "" {
			return nil, fmt.Errorf("GOTUNNEL_MYSQL_DSN not set")
		}
		return NewMySQL(dsn)

	case "sqlite":
		dbPath := os.Getenv("GOTUNNEL_SQLITE_DB_PATH")
		if dbPath == "" {
			dbPath = "./data/gotunnel.db"
		}

		// Ensure directory exists
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create db directory: %w", err)
		}

		return NewSQLite(dbPath)

	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}
}
