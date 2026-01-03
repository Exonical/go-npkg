package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// User represents a registry user
type User struct {
	Name      string    `json:"name"`
	Password  string    `json:"-"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	Tokens    []Token   `json:"-"`
}

// Token represents an authentication token
type Token struct {
	Value     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthManager handles user authentication
type AuthManager struct {
	users  map[string]*User
	tokens map[string]*User
	mu     sync.RWMutex
}

// NewAuthManager creates a new authentication manager
func NewAuthManager() *AuthManager {
	return &AuthManager{
		users:  make(map[string]*User),
		tokens: make(map[string]*User),
	}
}

// CreateUser creates a new user
func (am *AuthManager) CreateUser(name, password, email string) (*User, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.users[name]; exists {
		return nil, fmt.Errorf("user %s already exists", name)
	}

	user := &User{
		Name:      name,
		Password:  password, // In production, hash this!
		Email:     email,
		CreatedAt: time.Now(),
		Tokens:    []Token{},
	}

	am.users[name] = user
	return user, nil
}

// Authenticate validates credentials and returns a token
func (am *AuthManager) Authenticate(name, password string) (string, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, exists := am.users[name]
	if !exists {
		return "", fmt.Errorf("user not found")
	}

	// In production, compare hashed passwords!
	if user.Password != password {
		return "", fmt.Errorf("invalid password")
	}

	// Generate token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	tokenValue := hex.EncodeToString(tokenBytes)

	token := Token{
		Value:     tokenValue,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour * 30), // 30 days
	}

	user.Tokens = append(user.Tokens, token)
	am.tokens[tokenValue] = user

	return tokenValue, nil
}

// ValidateToken checks if a token is valid
func (am *AuthManager) ValidateToken(tokenValue string) (*User, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	user, exists := am.tokens[tokenValue]
	if !exists {
		return nil, fmt.Errorf("invalid token")
	}

	// Check if token is expired
	for _, token := range user.Tokens {
		if token.Value == tokenValue {
			if time.Now().After(token.ExpiresAt) {
				return nil, fmt.Errorf("token expired")
			}
			return user, nil
		}
	}

	return nil, fmt.Errorf("token not found")
}

// RevokeToken invalidates a token
func (am *AuthManager) RevokeToken(tokenValue string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, exists := am.tokens[tokenValue]
	if !exists {
		return fmt.Errorf("token not found")
	}

	// Remove token from user's tokens
	for i, token := range user.Tokens {
		if token.Value == tokenValue {
			user.Tokens = append(user.Tokens[:i], user.Tokens[i+1:]...)
			break
		}
	}

	delete(am.tokens, tokenValue)
	return nil
}

// AuthMiddleware creates an authentication middleware
func (am *AuthManager) AuthMiddleware(next http.HandlerFunc, required bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			if required {
				http.Error(w, "Authorization required", http.StatusUnauthorized)
				return
			}
			next(w, r)
			return
		}

		// Handle Bearer token
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			user, err := am.ValidateToken(token)
			if err != nil {
				if required {
					http.Error(w, "Invalid token", http.StatusUnauthorized)
					return
				}
			} else {
				// Add user to request context (simplified)
				r.Header.Set("X-User", user.Name)
			}
		}

		next(w, r)
	}
}

// HandleLogin handles user login requests
func (am *AuthManager) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginData struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Try to authenticate existing user
	token, err := am.Authenticate(loginData.Name, loginData.Password)
	if err != nil {
		// User doesn't exist, create new user
		_, err := am.CreateUser(loginData.Name, loginData.Password, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		token, err = am.Authenticate(loginData.Name, loginData.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":    true,
		"token": token,
	})
}

// HandleLogout handles user logout requests
func (am *AuthManager) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract token from URL or header
	authHeader := r.Header.Get("Authorization")
	var token string

	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		// Try to get from URL path
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) > 0 {
			token = parts[len(parts)-1]
		}
	}

	if token == "" {
		http.Error(w, "Token required", http.StatusBadRequest)
		return
	}

	if err := am.RevokeToken(token); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}
