package server

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"

	"gotunnel/internal/auth"
	"gotunnel/internal/database"
	"gotunnel/internal/tunnel"
)

//go:embed all:templates
var templatesFS embed.FS

//go:embed all:static
var staticFS embed.FS

// Server is the main server struct
type Server struct {
	config      *Config
	db          database.DB
	authService *auth.Service
	tunnelMgr   *tunnel.Manager
	templates   map[string]*template.Template
}

// New creates a new server instance
func New(config *Config) (*Server, error) {
	// Initialize database (reads from env vars)
	db, err := database.New()
	if err != nil {
		return nil, err
	}

	// Initialize services
	authSvc := auth.NewService(db, config.Secret)
	tunnelMgr := tunnel.NewManager(db, config.Domain)

	// Parse templates
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}

	return &Server{
		config:      config,
		db:          db,
		authService: authSvc,
		tunnelMgr:   tunnelMgr,
		templates:   tmpl,
	}, nil
}

func parseTemplates() (map[string]*template.Template, error) {
	funcMap := template.FuncMap{
		"statusColor": func(status string) string {
			if status == "online" {
				return "text-green-400"
			}
			return "text-gray-400"
		},
		"statusBadge": func(status string) string {
			if status == "online" {
				return "bg-green-500/20 text-green-400"
			}
			return "bg-gray-500/20 text-gray-400"
		},
		"methodColor": func(method string) string {
			switch method {
			case "GET":
				return "text-blue-400"
			case "POST":
				return "text-purple-400"
			case "PUT", "PATCH":
				return "text-yellow-400"
			case "DELETE":
				return "text-red-400"
			default:
				return "text-gray-400"
			}
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
	}

	// Parse the shared base templates (base.html + sidebar.html)
	base, err := template.New("").Funcs(funcMap).ParseFS(templatesFS, "templates/base.html", "templates/sidebar.html")
	if err != nil {
		return nil, fmt.Errorf("parsing base templates: %w", err)
	}

	// Page templates to load
	pages := []string{
		"home.html",
		"login.html",
		"register.html",
		"dashboard.html",
		"tunnels.html",
		"install.html",
		"settings.html",
		"logs.html",
		"admin-users.html",
	}

	templates := make(map[string]*template.Template)
	for _, page := range pages {
		// Clone the base template set, then parse the page-specific template into it
		t, err := template.Must(base.Clone()).ParseFS(templatesFS, "templates/"+page)
		if err != nil {
			return nil, fmt.Errorf("parsing template %s: %w", page, err)
		}
		templates[page] = t
	}

	return templates, nil
}

// adminHandler returns the HTTP handler for the admin/dashboard server
func (s *Server) adminHandler() http.Handler {
	mux := http.NewServeMux()

	// Serve static files
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("Failed to get static subtree: %v", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Public routes
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/download/", s.handleDownload)

	// Protected routes (dashboard)
	mux.HandleFunc("/dashboard", s.requireAuth(s.handleDashboard))
	mux.HandleFunc("/dashboard/tunnels", s.requireAuth(s.handleTunnels))
	mux.HandleFunc("/dashboard/install", s.requireAuth(s.handleInstall))
	mux.HandleFunc("/dashboard/settings", s.requireAuth(s.handleSettings))
	mux.HandleFunc("/dashboard/logs/", s.requireAuth(s.handleLogs))

	// Admin routes
	mux.HandleFunc("/admin/users", s.requireAdmin(s.handleAdminUsers))
	mux.HandleFunc("/admin/impersonate/", s.requireAdmin(s.handleAdminImpersonate))
	mux.HandleFunc("/admin/stop-impersonate", s.requireAuth(s.handleAdminStopImpersonate))

	// API routes
	mux.HandleFunc("/api/tunnels", s.requireAuth(s.handleAPITunnels))
	mux.HandleFunc("/api/tunnels/reserve", s.requireAuth(s.handleAPIReserveTunnel))
	mux.HandleFunc("/api/tunnels/delete", s.requireAuth(s.handleAPIDeleteTunnel))
	mux.HandleFunc("/api/token/regenerate", s.requireAuth(s.handleAPIRegenerateToken))
	mux.HandleFunc("/api/password/change", s.requireAuth(s.handleAPIChangePassword))
	mux.HandleFunc("/api/stats", s.requireAuth(s.handleAPIStats))
	mux.HandleFunc("/api/admin/users/update", s.requireAdmin(s.handleAPIAdminUpdateUser))
	mux.HandleFunc("/api/admin/users/delete", s.requireAdmin(s.handleAPIAdminDeleteUser))
	mux.HandleFunc("/api/admin/users/reset-password", s.requireAdmin(s.handleAPIAdminResetPassword))

	// WebSocket tunnel endpoint
	mux.HandleFunc("/ws/tunnel", s.handleTunnelWebSocket)

	return s.withLogging(mux)
}
