package session

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Installation represents a GitHub App installation
type Installation struct {
	ID            int64                    `json:"id"`
	Account       string                   `json:"account"`
	Permissions   map[string]interface{}   `json:"permissions"`
	RepositoryIDs []int64                 `json:"repository_ids,omitempty"`
}

// Session represents an authenticated user session
type Session struct {
	AccessToken    string
	CreatedAt     time.Time
	RedirectURI   string
	LastAccess    time.Time
	Installations []Installation
	Scope         string
	AccountType   string
	AccountLogin  string
}

const (
	sessionTimeout   = 24 * time.Hour // Sessions expire after 24 hours of inactivity
	cleanupInterval = time.Hour       // Run cleanup every hour
)

var (
	sessionStore  = map[string]*Session{}
	sessionMu     sync.Mutex
	SessionCookie = "mcp_session"     // Exported for use in other packages
)

var (
	stateStore  = map[string]string{}
	stateMu     sync.Mutex
)

// StoreState stores state information for PKCE flow
func StoreState(state, value string) {
	stateMu.Lock()
	defer stateMu.Unlock()
	stateStore[state] = value
}

// PopState retrieves and removes state information
func PopState(state string) string {
	stateMu.Lock()
	defer stateMu.Unlock()
	if value, ok := stateStore[state]; ok {
		delete(stateStore, state)
		return value
	}
	return ""
}

// Create creates a new session with the given token and redirect URI
func Create(token, redirectURI string) (string, error) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	// Generate session ID (you may want to use a more secure method in production)
	sessionID := generateID()

	session := &Session{
		AccessToken:  token,
		CreatedAt:   time.Now(),
		LastAccess:  time.Now(),
		RedirectURI: redirectURI,
	}

	sessionStore[sessionID] = session
	log.Printf("[DEBUG] Created new session - ID: %s, URI: %s", sessionID, redirectURI)
	return sessionID, nil
}

// GenerateID generates a random session ID
func GenerateID() string {
	// In a production system, use a more secure method
	return fmt.Sprintf("%s_%d", time.Now().Format("20060102150405"), time.Now().UnixNano())
}

// generateID is an internal alias for GenerateID
func generateID() string {
	return GenerateID()
}

// Get retrieves a session by ID
func Get(id string) *Session {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if session := sessionStore[id]; session != nil {
		session.LastAccess = time.Now()
		log.Printf("[DEBUG] Retrieved active session - ID: %s, Token: %s***, Last Access: %v", 
			id, session.AccessToken[:10], session.LastAccess)
		return session
	}
	log.Printf("[DEBUG] No session found for ID: %s", id)
	return nil
}

// cleanupSessions removes expired sessions
func cleanupSessions() {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	
	now := time.Now()
	for id, session := range sessionStore {
		if now.Sub(session.LastAccess) > sessionTimeout {
			delete(sessionStore, id)
		}
	}
}

// StartCleanupRoutine starts the session cleanup goroutine
func StartCleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	go func() {
		for {
			select {
			case <-ticker.C:
				cleanupSessions()
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

// CleanupAll removes all sessions from the store
func CleanupAll() {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	for id := range sessionStore {
		delete(sessionStore, id)
	}
}