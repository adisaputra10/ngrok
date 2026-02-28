package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	"gotunnel/internal/auth"
)

// handleGoogleLogin redirects to Google OAuth consent screen
func (s *Server) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	if s.config.GoogleClientID == "" {
		http.Error(w, "Google OAuth not configured", http.StatusInternalServerError)
		return
	}

	// Generate random state for CSRF protection
	state := generateRandomString(32)

	// Store state in session (we'll use a simple in-memory store or cookie)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Build Google OAuth URL
	googleAuthURL := url.URL{
		Scheme: "https",
		Host:   "accounts.google.com",
		Path:   "/o/oauth2/v2/auth",
	}

	q := googleAuthURL.Query()
	q.Set("client_id", s.config.GoogleClientID)
	q.Set("redirect_uri", s.config.GoogleRedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	googleAuthURL.RawQuery = q.Encode()

	http.Redirect(w, r, googleAuthURL.String(), http.StatusTemporaryRedirect)
}

// handleGoogleCallback handles the callback from Google OAuth
func (s *Server) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if s.config.GoogleClientID == "" {
		http.Error(w, "Google OAuth not configured", http.StatusInternalServerError)
		return
	}

	// Verify state parameter
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "Missing oauth_state cookie", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if state != stateCookie.Value {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	token, err := exchangeCodeForToken(code, s.config.GoogleClientID, s.config.GoogleClientSecret, s.config.GoogleRedirectURL)
	if err != nil {
		log.Printf("[oauth] Token exchange failed: %v", err)
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	// Get user info from Google
	googleUser, err := getGoogleUserInfo(token)
	if err != nil {
		log.Printf("[oauth] Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info from Google", http.StatusInternalServerError)
		return
	}

	// Find or create user
	user, err := s.db.GetUserByEmail(googleUser.Email)
	if err != nil {
		// User doesn't exist, create new one via OAuth path (no password required)
		if !s.config.AllowRegistration {
			http.Error(w, "Registration is disabled", http.StatusForbidden)
			return
		}

		user, err = s.authService.RegisterOAuth(googleUser.Email, googleUser.Name)
		if err != nil {
			log.Printf("[oauth] Failed to create user: %v", err)
			http.Error(w, "Failed to create user account: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Create session
	sessionID, err := s.authService.CreateSession(user.ID)
	if err != nil {
		log.Printf("[oauth] Failed to create session: %v", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	auth.SetSessionCookie(w, sessionID)

	log.Printf("[oauth] User logged in via Google: %s (id: %d)", user.Email, user.ID)

	// Redirect to dashboard
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// exchangeCodeForToken exchanges authorization code for access token
func exchangeCodeForToken(code, clientID, clientSecret, redirectURL string) (string, error) {
	tokenURL := "https://oauth2.googleapis.com/token"

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {redirectURL},
	}

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	if result.Error != "" {
		return "", fmt.Errorf("token exchange error: %s", result.Error)
	}

	return result.AccessToken, nil
}

// GoogleUserInfo holds user info from Google
type GoogleUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// getGoogleUserInfo fetches user info using access token
func getGoogleUserInfo(accessToken string) (*GoogleUserInfo, error) {
	userInfoURL := "https://www.googleapis.com/oauth2/v2/userinfo?alt=json"

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var userInfo GoogleUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	return &userInfo, nil
}

// generateRandomString generates a cryptographically random hex string
func generateRandomString(length int) string {
	bytes := make([]byte, length/2+1)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)[:length]
}
