package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gotunnel/internal/database"
	"gotunnel/internal/models"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Service handles authentication logic
type Service struct {
	db     database.DB
	secret string
}

// NewService creates a new auth service
func NewService(db database.DB, secret string) *Service {
	return &Service{db: db, secret: secret}
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword compares a password with a hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateAuthToken generates a random auth token
func GenerateAuthToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return "gt_" + hex.EncodeToString(bytes)
}

// GenerateSessionID generates a random session ID
func GenerateSessionID() string {
	return uuid.New().String()
}

// Register creates a new user account
func (s *Service) Register(email, username, password string) (*models.User, error) {
	// Validate inputs
	email = strings.TrimSpace(strings.ToLower(email))
	username = strings.TrimSpace(strings.ToLower(username))

	if len(email) < 3 || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("invalid email address")
	}
	if len(username) < 3 || len(username) > 32 {
		return nil, fmt.Errorf("username must be 3-32 characters")
	}
	if len(password) < 6 {
		return nil, fmt.Errorf("password must be at least 6 characters")
	}

	// Check for valid username characters
	for _, c := range username {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return nil, fmt.Errorf("username can only contain lowercase letters, numbers, hyphens, and underscores")
		}
	}

	// Check if email/username already exists
	if _, err := s.db.GetUserByEmail(email); err == nil {
		return nil, fmt.Errorf("email already registered")
	}
	if _, err := s.db.GetUserByUsername(username); err == nil {
		return nil, fmt.Errorf("username already taken")
	}

	// Hash password
	hash, err := HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate auth token
	authToken := GenerateAuthToken()

	// Create user
	user, err := s.db.CreateUser(email, username, hash, authToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Make first user an admin
	count, _ := s.db.UserCount()
	if count == 1 {
		s.db.UpdateUserAdmin(user.ID, true)
		user.IsAdmin = true
	}

	return user, nil
}

// Login authenticates a user and creates a session
func (s *Service) Login(emailOrUsername, password string) (*models.User, string, error) {
	emailOrUsername = strings.TrimSpace(strings.ToLower(emailOrUsername))

	// Try to find by email first, then username
	user, err := s.db.GetUserByEmail(emailOrUsername)
	if err != nil {
		user, err = s.db.GetUserByUsername(emailOrUsername)
		if err != nil {
			return nil, "", fmt.Errorf("invalid credentials")
		}
	}

	// Check password
	if !CheckPassword(password, user.PasswordHash) {
		return nil, "", fmt.Errorf("invalid credentials")
	}

	// Create session
	sessionID := GenerateSessionID()
	expiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days

	if err := s.db.CreateSession(sessionID, user.ID, expiresAt); err != nil {
		return nil, "", fmt.Errorf("failed to create session: %w", err)
	}

	return user, sessionID, nil
}

// CreateSession creates a new session for a user (used by OAuth handlers)
func (s *Service) CreateSession(userID int64) (string, error) {
	sessionID := GenerateSessionID()
	expiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days

	if err := s.db.CreateSession(sessionID, userID, expiresAt); err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	return sessionID, nil
}

// ValidateSession checks if a session is valid and returns the user
func (s *Service) ValidateSession(sessionID string) (*models.User, error) {
	session, err := s.db.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session")
	}

	user, err := s.db.GetUserByID(session.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

// ValidateAuthToken checks if an auth token is valid and returns the user
func (s *Service) ValidateAuthToken(token string) (*models.User, error) {
	user, err := s.db.GetUserByAuthToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid auth token")
	}
	return user, nil
}

// Logout removes a session
func (s *Service) Logout(sessionID string) error {
	return s.db.DeleteSession(sessionID)
}

// RegenerateToken creates a new auth token for a user
func (s *Service) RegenerateToken(userID int64) (string, error) {
	newToken := GenerateAuthToken()
	if err := s.db.UpdateUserToken(userID, newToken); err != nil {
		return "", err
	}
	return newToken, nil
}

// GetUserFromRequest extracts the user from the session cookie
func (s *Service) GetUserFromRequest(r *http.Request) (*models.User, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil, fmt.Errorf("no session cookie")
	}
	return s.ValidateSession(cookie.Value)
}

// SetSessionCookie sets the session cookie on the response
func SetSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 60 * 60, // 7 days
	})
}

// ClearSessionCookie removes the session cookie
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}
