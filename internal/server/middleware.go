package server

import (
	"log"
	"net/http"
	"time"

	"gotunnel/internal/models"
)

// withLogging adds request logging middleware
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip wrapping for WebSocket upgrades — the Hijacker interface must not be obscured
		if r.Header.Get("Upgrade") == "websocket" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(wrapped, r)
		log.Printf("[admin] %s %s %d %s", r.Method, r.URL.Path, wrapped.status, time.Since(start).Round(time.Millisecond))
	})
}

// requireAuth is middleware that checks for a valid session
func (s *Server) requireAuth(handler func(w http.ResponseWriter, r *http.Request, user *models.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := s.authService.GetUserFromRequest(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		handler(w, r, user)
	}
}

// requireAdmin is middleware that checks for a valid admin session
func (s *Server) requireAdmin(handler func(w http.ResponseWriter, r *http.Request, user *models.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If impersonating, use the admin_session for admin check
		var adminUser *models.User
		if ac, err := r.Cookie("admin_session"); err == nil && ac.Value != "" {
			adminUser, _ = s.authService.ValidateSession(ac.Value)
		}
		if adminUser == nil {
			adminUser, _ = s.authService.GetUserFromRequest(r)
		}
		// Not logged in → redirect to login
		if adminUser == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Logged in but not admin → 403
		if !adminUser.IsAdmin {
			http.Error(w, "Forbidden: admin access required", http.StatusForbidden)
			return
		}
		handler(w, r, adminUser)
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
