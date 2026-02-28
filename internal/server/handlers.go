package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gotunnel/internal/auth"
	"gotunnel/internal/models"
)

// --- Template data structures ---

type pageData struct {
	User               *models.User
	Domain             string
	AllowRegistration  bool
	Flash              string
	FlashType          string // success, error, info
	Data               interface{}
	ImpersonatingAdmin *models.User // non-nil when an admin is viewing as this user
}

type dashboardData struct {
	Stats       *models.TunnelStats
	Tunnels     []*models.Tunnel
	Connections []*models.ConnectionInfo
}

type tunnelsData struct {
	Tunnels     []*models.Tunnel
	Connections []*models.ConnectionInfo
	Domain      string
}

type installData struct {
	Domain    string
	AuthToken string
	AdminPort string
}

type settingsData struct {
	AuthToken string
}

type logsData struct {
	Tunnel *models.Tunnel
	Logs   []*models.RequestLog
	Domain string
}

// --- Page Handlers ---

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// If already logged in, redirect to dashboard
	if user, err := s.authService.GetUserFromRequest(r); err == nil && user != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	s.render(w, r, "home.html", &pageData{
		Domain:            s.config.Domain,
		AllowRegistration: s.config.AllowRegistration,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.render(w, r, "login.html", &pageData{
			Domain:            s.config.Domain,
			AllowRegistration: s.config.AllowRegistration,
		})
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")

	user, sessionID, err := s.authService.Login(email, password)
	if err != nil {
		s.render(w, r, "login.html", &pageData{
			Domain:            s.config.Domain,
			AllowRegistration: s.config.AllowRegistration,
			Flash:             "Invalid email/username or password",
			FlashType:         "error",
		})
		return
	}

	auth.SetSessionCookie(w, sessionID)
	log.Printf("[auth] User logged in: %s (id: %d)", user.Username, user.ID)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.config.AllowRegistration {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		s.render(w, r, "register.html", &pageData{
			Domain:            s.config.Domain,
			AllowRegistration: s.config.AllowRegistration,
		})
		return
	}

	// POST - process registration
	email := strings.TrimSpace(r.FormValue("email"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if password != confirmPassword {
		s.render(w, r, "register.html", &pageData{
			Domain:            s.config.Domain,
			AllowRegistration: s.config.AllowRegistration,
			Flash:             "Passwords do not match",
			FlashType:         "error",
		})
		return
	}

	user, err := s.authService.Register(email, username, password)
	if err != nil {
		s.render(w, r, "register.html", &pageData{
			Domain:            s.config.Domain,
			AllowRegistration: s.config.AllowRegistration,
			Flash:             err.Error(),
			FlashType:         "error",
		})
		return
	}

	// Auto-login after registration
	_, sessionID, err := s.authService.Login(email, password)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	auth.SetSessionCookie(w, sessionID)
	log.Printf("[auth] New user registered: %s (id: %d)", user.Username, user.ID)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		s.authService.Logout(cookie.Value)
	}
	auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleDownload serves pre-built client binaries from the downloads/ directory
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/download/")
	if filename == "" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Only allow known binary filenames (prevent directory traversal)
	allowed := map[string]bool{
		"demolocal-linux-amd64":       true,
		"demolocal-linux-arm64":       true,
		"demolocal-darwin-amd64":      true,
		"demolocal-darwin-arm64":      true,
		"demolocal-windows-amd64.exe": true,
	}
	if !allowed[filename] {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	filepath := "downloads/" + filename
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, filepath)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, user *models.User) {
	stats, _ := s.db.GetStats(user.ID)
	tunnels, _ := s.db.GetTunnelsByUserID(user.ID)
	connections := s.tunnelMgr.GetActiveConnectionsForUser(user.ID)

	// Update tunnel statuses based on active connections
	activeSubdomains := make(map[string]bool)
	for _, c := range connections {
		activeSubdomains[c.Subdomain] = true
	}
	for _, t := range tunnels {
		if activeSubdomains[t.Subdomain] {
			t.Status = "online"
		} else {
			t.Status = "offline"
		}
	}

	s.render(w, r, "dashboard.html", &pageData{
		User:   user,
		Domain: s.config.Domain,
		Data: dashboardData{
			Stats:       stats,
			Tunnels:     tunnels,
			Connections: connections,
		},
	})
}

func (s *Server) handleTunnels(w http.ResponseWriter, r *http.Request, user *models.User) {
	tunnels, _ := s.db.GetTunnelsByUserID(user.ID)
	connections := s.tunnelMgr.GetActiveConnectionsForUser(user.ID)

	activeSubdomains := make(map[string]bool)
	for _, c := range connections {
		activeSubdomains[c.Subdomain] = true
	}
	for _, t := range tunnels {
		if activeSubdomains[t.Subdomain] {
			t.Status = "online"
		} else {
			t.Status = "offline"
		}
	}

	s.render(w, r, "tunnels.html", &pageData{
		User:   user,
		Domain: s.config.Domain,
		Data: tunnelsData{
			Tunnels:     tunnels,
			Connections: connections,
			Domain:      s.config.Domain,
		},
	})
}

func (s *Server) handleInstall(w http.ResponseWriter, r *http.Request, user *models.User) {
	s.render(w, r, "install.html", &pageData{
		User:   user,
		Domain: s.config.Domain,
		Data: installData{
			Domain:    s.config.Domain,
			AuthToken: user.AuthToken,
			AdminPort: s.config.AdminPort,
		},
	})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, user *models.User) {
	s.render(w, r, "settings.html", &pageData{
		User:   user,
		Domain: s.config.Domain,
		Data: settingsData{
			AuthToken: user.AuthToken,
		},
	})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request, user *models.User) {
	// Parse tunnel ID from URL: /dashboard/logs/{id}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/dashboard/logs/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Redirect(w, r, "/dashboard/tunnels", http.StatusSeeOther)
		return
	}

	tunnelID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Redirect(w, r, "/dashboard/tunnels", http.StatusSeeOther)
		return
	}

	t, err := s.db.GetTunnelByID(tunnelID)
	if err != nil || t.UserID != user.ID {
		http.NotFound(w, r)
		return
	}

	logs, _ := s.db.GetRecentLogs(tunnelID, 100)

	s.render(w, r, "logs.html", &pageData{
		User:   user,
		Domain: s.config.Domain,
		Data: logsData{
			Tunnel: t,
			Logs:   logs,
			Domain: s.config.Domain,
		},
	})
}

// --- API Handlers ---

func (s *Server) handleAPITunnels(w http.ResponseWriter, r *http.Request, user *models.User) {
	tunnels, err := s.db.GetTunnelsByUserID(user.ID)
	if err != nil {
		jsonError(w, "Failed to get tunnels", 500)
		return
	}
	connections := s.tunnelMgr.GetActiveConnectionsForUser(user.ID)

	activeSubdomains := make(map[string]bool)
	for _, c := range connections {
		activeSubdomains[c.Subdomain] = true
	}
	for _, t := range tunnels {
		if activeSubdomains[t.Subdomain] {
			t.Status = "online"
		}
	}

	jsonResponse(w, tunnels)
}

func (s *Server) handleAPIReserveTunnel(w http.ResponseWriter, r *http.Request, user *models.User) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", 400)
		return
	}

	subdomain := strings.TrimSpace(strings.ToLower(req.Subdomain))
	if subdomain == "" {
		jsonError(w, "Subdomain is required", 400)
		return
	}

	// Check max tunnels
	tunnels, _ := s.db.GetTunnelsByUserID(user.ID)
	if len(tunnels) >= user.MaxTunnels {
		jsonError(w, fmt.Sprintf("Maximum %d tunnels allowed", user.MaxTunnels), 400)
		return
	}

	// Check if subdomain is already taken
	existing, err := s.db.GetTunnelBySubdomain(subdomain)
	if err == nil && existing.UserID != user.ID {
		jsonError(w, "Subdomain is already reserved by another user", 400)
		return
	}

	if existing != nil && existing.UserID == user.ID {
		jsonResponse(w, existing)
		return
	}

	tunnel, err := s.db.CreateTunnel(user.ID, subdomain, true)
	if err != nil {
		jsonError(w, "Failed to reserve subdomain: "+err.Error(), 500)
		return
	}

	jsonResponse(w, tunnel)
}

func (s *Server) handleAPIDeleteTunnel(w http.ResponseWriter, r *http.Request, user *models.User) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		TunnelID int64 `json:"tunnel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", 400)
		return
	}

	if err := s.db.DeleteTunnel(req.TunnelID, user.ID); err != nil {
		jsonError(w, "Failed to delete tunnel", 500)
		return
	}

	jsonResponse(w, map[string]string{"status": "deleted"})
}

func (s *Server) handleAPIRegenerateToken(w http.ResponseWriter, r *http.Request, user *models.User) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	newToken, err := s.authService.RegenerateToken(user.ID)
	if err != nil {
		jsonError(w, "Failed to regenerate token", 500)
		return
	}

	jsonResponse(w, map[string]string{"auth_token": newToken})
}

func (s *Server) handleAPIChangePassword(w http.ResponseWriter, r *http.Request, user *models.User) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", 400)
		return
	}

	if !auth.CheckPassword(req.CurrentPassword, user.PasswordHash) {
		jsonError(w, "Current password is incorrect", 400)
		return
	}

	if len(req.NewPassword) < 6 {
		jsonError(w, "New password must be at least 6 characters", 400)
		return
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		jsonError(w, "Failed to hash password", 500)
		return
	}

	if err := s.db.UpdateUserPassword(user.ID, hash); err != nil {
		jsonError(w, "Failed to update password", 500)
		return
	}

	jsonResponse(w, map[string]string{"status": "password_changed"})
}

func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request, user *models.User) {
	stats, err := s.db.GetStats(user.ID)
	if err != nil {
		jsonError(w, "Failed to get stats", 500)
		return
	}
	jsonResponse(w, stats)
}

// --- Admin Handlers ---

type adminUsersData struct {
	Users []*models.User
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request, user *models.User) {
	users, _ := s.db.GetAllUsers()
	s.render(w, r, "admin-users.html", &pageData{
		User:   user,
		Domain: s.config.Domain,
		Data:   adminUsersData{Users: users},
	})
}

// handleAdminImpersonate creates a session for a target user, saving the admin session aside
func (s *Server) handleAdminImpersonate(w http.ResponseWriter, r *http.Request, user *models.User) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/impersonate/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		jsonError(w, "User ID required", 400)
		return
	}
	targetID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || targetID == user.ID {
		jsonError(w, "Invalid user ID", 400)
		return
	}

	target, err := s.db.GetUserByID(targetID)
	if err != nil {
		jsonError(w, "User not found", 404)
		return
	}

	// Save the current admin session cookie value
	adminCookie, _ := r.Cookie("session_id")
	adminSessionVal := ""
	if adminCookie != nil {
		adminSessionVal = adminCookie.Value
	}

	// Create a new session for the target user
	sessionID := auth.GenerateSessionID()
	if err := s.db.CreateSession(sessionID, target.ID, time.Now().Add(7*24*time.Hour)); err != nil {
		jsonError(w, "Failed to create session", 500)
		return
	}

	// Save admin session in a separate cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    adminSessionVal,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 60 * 60,
	})

	// Switch current session to the impersonated user
	auth.SetSessionCookie(w, sessionID)
	log.Printf("[admin] %s (id:%d) is now impersonating %s (id:%d)", user.Username, user.ID, target.Username, target.ID)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// handleAdminStopImpersonate ends impersonation and restores the original admin session
func (s *Server) handleAdminStopImpersonate(w http.ResponseWriter, r *http.Request, user *models.User) {
	// Delete the impersonated session
	if cookie, err := r.Cookie("session_id"); err == nil {
		s.authService.Logout(cookie.Value)
	}

	// Restore admin session
	adminCookie, err := r.Cookie("admin_session")
	if err != nil || adminCookie.Value == "" {
		auth.ClearSessionCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	auth.SetSessionCookie(w, adminCookie.Value)
	// Clear the admin_session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	log.Printf("[admin] Stopped impersonating user %s, restored admin session", user.Username)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// handleAPIAdminUpdateUser updates a user's role or max tunnels
func (s *Server) handleAPIAdminUpdateUser(w http.ResponseWriter, r *http.Request, user *models.User) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		UserID     int64 `json:"user_id"`
		IsAdmin    *bool `json:"is_admin"`
		MaxTunnels *int  `json:"max_tunnels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", 400)
		return
	}

	if req.UserID == user.ID {
		jsonError(w, "Cannot modify your own admin status", 400)
		return
	}

	target, err := s.db.GetUserByID(req.UserID)
	if err != nil {
		jsonError(w, "User not found", 404)
		return
	}

	if req.IsAdmin != nil {
		if err := s.db.UpdateUserAdmin(req.UserID, *req.IsAdmin); err != nil {
			jsonError(w, "Failed to update role", 500)
			return
		}
		target.IsAdmin = *req.IsAdmin
	}

	if req.MaxTunnels != nil {
		if *req.MaxTunnels < 0 || *req.MaxTunnels > 100 {
			jsonError(w, "Max tunnels must be between 0 and 100", 400)
			return
		}
		if err := s.db.UpdateUserMaxTunnels(req.UserID, *req.MaxTunnels); err != nil {
			jsonError(w, "Failed to update max tunnels", 500)
			return
		}
		target.MaxTunnels = *req.MaxTunnels
	}

	jsonResponse(w, target)
}

// handleAPIAdminDeleteUser deletes a user account
func (s *Server) handleAPIAdminDeleteUser(w http.ResponseWriter, r *http.Request, user *models.User) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		UserID int64 `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", 400)
		return
	}

	if req.UserID == user.ID {
		jsonError(w, "Cannot delete your own account", 400)
		return
	}

	if err := s.db.DeleteUser(req.UserID); err != nil {
		jsonError(w, "Failed to delete user: "+err.Error(), 500)
		return
	}

	jsonResponse(w, map[string]string{"status": "deleted"})
}

// handleAPIAdminResetPassword allows admin to reset any user's password
func (s *Server) handleAPIAdminResetPassword(w http.ResponseWriter, r *http.Request, user *models.User) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		UserID      int64  `json:"user_id"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", 400)
		return
	}

	if len(req.NewPassword) < 6 {
		jsonError(w, "Password must be at least 6 characters", 400)
		return
	}

	if _, err := s.db.GetUserByID(req.UserID); err != nil {
		jsonError(w, "User not found", 404)
		return
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		jsonError(w, "Failed to hash password", 500)
		return
	}

	if err := s.db.UpdateUserPassword(req.UserID, hash); err != nil {
		jsonError(w, "Failed to update password", 500)
		return
	}

	log.Printf("[admin] %s (id:%d) reset password for user id:%d", user.Username, user.ID, req.UserID)
	jsonResponse(w, map[string]string{"status": "password_reset"})
}

// handleTunnelWebSocket handles WebSocket connections for tunnels (uses auth token, not session)
func (s *Server) handleTunnelWebSocket(w http.ResponseWriter, r *http.Request) {	// Authenticate via auth token (query param or header)
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}
	}

	if token == "" {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	user, err := s.authService.ValidateAuthToken(token)
	if err != nil {
		http.Error(w, "Invalid auth token", http.StatusUnauthorized)
		return
	}

	s.tunnelMgr.HandleWebSocket(w, r, user)
}

// --- Helpers ---

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data *pageData) {
	// Auto-populate impersonation info from admin_session cookie
	if data != nil {
		if cookie, err := r.Cookie("admin_session"); err == nil && cookie.Value != "" {
			if adminUser, err := s.authService.ValidateSession(cookie.Value); err == nil && adminUser.IsAdmin {
				data.ImpersonatingAdmin = adminUser
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl, ok := s.templates[name]
	if !ok {
		log.Printf("[render] Template %s not found", name)
		http.Error(w, "Internal server error", 500)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		log.Printf("[render] Error rendering %s: %v", name, err)
		http.Error(w, "Internal server error", 500)
	}
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
