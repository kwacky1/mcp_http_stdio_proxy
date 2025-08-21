package auth

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"bytes"
	"strings"
	"sync"
	"time"

	"github.com/kwacky1/mcp_http_stdio_proxy/internal/session"
)

// Handler manages GitHub App authentication and OAuth flows
type Handler struct {
	config Config
	privateKeyMu sync.RWMutex
	parsedPrivateKey *rsa.PrivateKey
}

// OpenIDConfig serves the OpenID Connect configuration
func (h *Handler) OpenIDConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serverURL := h.config.ServerURL
	config := map[string]interface{}{
		"issuer":                            serverURL,
		"authorization_endpoint":            fmt.Sprintf("%s/oauth/authorize", serverURL),
		"token_endpoint":                   fmt.Sprintf("%s/oauth/token", serverURL),
		"registration_endpoint":            fmt.Sprintf("%s/oauth/register", serverURL),
		"userinfo_endpoint":               fmt.Sprintf("%s/oauth/userinfo", serverURL),
		"response_types_supported":         []string{"code"},
		"subject_types_supported":         []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":               []string{"user", "repo", "read:org"},
		"token_endpoint_auth_methods":    []string{"none"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"claims_supported":              []string{"sub", "name", "preferred_username", "profile", "picture", "website", "email", "email_verified", "updated_at"},
		"client_id":                     h.config.ClientID,
		"code_challenge_methods_supported": []string{"S256"},
		"grant_types_supported":         []string{"authorization_code"},
		"service_documentation":         fmt.Sprintf("%s/.well-known/oauth-authorization-server", serverURL),
		"registration_endpoint_json_types": []string{"application/json"},
	}

	log.Printf("OpenID config response: %+v", config)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// Register handles dynamic client registration
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] Register handler called with method: %s", r.Method)
	
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var registration struct {
		ClientName    string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}

	if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
		log.Printf("[ERROR] Failed to decode registration request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("[DEBUG] Registration request - name: %s, redirects: %v", registration.ClientName, registration.RedirectURIs)

	// Always use our configured client ID for VS Code
	response := map[string]interface{}{
		"client_id":                h.config.ClientID,
		"client_id_issued_at":      time.Now().Unix(),
		"client_secret":            "",  // No secret needed for PKCE
		"client_secret_expires_at": 0,
		"registration_access_token": "",  // Not needed for our use case
		"registration_client_uri":  fmt.Sprintf("%s/oauth/register/%s", h.config.ServerURL, h.config.ClientID),
		"client_name":              registration.ClientName,
		"redirect_uris":            registration.RedirectURIs,
		"grant_types":              []string{"authorization_code"},
		"response_types":           []string{"code"},
		"token_endpoint_auth_method": "none",  // We use PKCE instead
		"scope":                    "user repo read:org",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Authorize handles the authorization request
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] Authorize handler called with URL: %s", r.URL.String())
	
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get authorization parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	
	log.Printf("[DEBUG] Auth parameters - clientID: %s, expected clientID: %s", clientID, h.config.ClientID)

	// Validate client_id
	if !h.IsValidClientID(clientID) {
		log.Printf("[ERROR] Invalid client_id: %s", clientID)
		http.Error(w, "Invalid client_id", http.StatusBadRequest)
		return
	}
	
	log.Printf("[DEBUG] Client ID validation passed")

	// Store PKCE parameters in state for later verification
	if codeChallenge != "" {
		if codeChallengeMethod != "S256" {
			http.Error(w, "code_challenge_method must be S256", http.StatusBadRequest)
			return
		}
		
		// Use state to store PKCE data
		if state == "" {
			state = fmt.Sprintf("pkce_%s", session.GenerateID())
		}
		
		// Store PKCE parameters with state
		session.StoreState(state+"_cc", codeChallenge)
		session.StoreState(state+"_ccm", codeChallengeMethod)
	}

	// Build GitHub authorization URL
	authURL := fmt.Sprintf("%s/login/oauth/authorize", h.config.GithubHost)
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	if state != "" {
		q.Set("state", state)
	}

	// Get requested scopes from the original request
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = "user repo read:org" // Default scopes if none requested
	}
	q.Set("scope", scope)
	
	log.Printf("[DEBUG] Requesting GitHub authorization with scope: %s", scope)

	// Redirect to GitHub authorization page
	http.Redirect(w, r, authURL+"?"+q.Encode(), http.StatusFound)
}

// UserInfo returns information about the authenticated user
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Get user info from GitHub
	userInfo, err := h.getUserInfo(token)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Return user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

// Callback handles the OAuth callback from GitHub
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] Callback handler hit with URL: %s", r.URL.String())
	
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")
	
	log.Printf("[DEBUG] Callback params - code: %v, state: %s, redirect: %s", 
		code != "", state, redirectURI)

	if code == "" {
		err := r.URL.Query().Get("error")
		errDesc := r.URL.Query().Get("error_description")
		log.Printf("OAuth callback error: %s - %s", err, errDesc)
		http.Error(w, "Authorization failed", http.StatusBadRequest)
		return
	}

	if redirectURI == "" {
		redirectURI = h.config.ServerURL + "/oauth/callback"
	}

	// If this is a VS Code callback, redirect with the code
	if strings.Contains(redirectURI, "vscode://") ||
	   strings.Contains(redirectURI, "vscode-insiders://") ||
	   strings.Contains(redirectURI, "127.0.0.1:") ||
	   strings.Contains(redirectURI, "localhost:") {
		q := url.Values{}
		q.Set("code", code)
		if state != "" {
			q.Set("state", state)
		}
		http.Redirect(w, r, redirectURI+"?"+q.Encode(), http.StatusFound)
		return
	}

	// For browser flows, exchange code for token here
	tokenURL := fmt.Sprintf("%s/login/oauth/access_token", h.config.GithubHost)
	tokenData := map[string]interface{}{
		"client_id": h.config.ClientID,
		"code": code,
		"redirect_uri": redirectURI,
	}

	jsonData, err := json.Marshal(tokenData)
	if err != nil {
		log.Printf("Failed to marshal token request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create token request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Token request failed: %v", err)
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var oauthResp struct {
		AccessToken string `json:"access_token"`
		TokenType  string `json:"token_type"`
		Scope     string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&oauthResp); err != nil {
		log.Printf("Failed to decode token response: %v", err)
		http.Error(w, "Invalid token response", http.StatusInternalServerError)
		return
	}

	// Create a session with the token
	sessionID, err := session.Create(oauthResp.AccessToken, redirectURI)
	if err != nil {
		log.Printf("Session creation failed: %v", err)
		http.Error(w, "Session creation failed", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	cookie := &http.Cookie{
		Name:     session.SessionCookie,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// For browser flows, redirect to success page
	if state != "" && strings.HasPrefix(state, "http") {
		http.Redirect(w, r, state, http.StatusFound)
		return
	}

	// Show simple success message
	w.Write([]byte("Authentication successful! You can close this window."))
}

// Config holds the configuration for the auth handler
type Config struct {
	AppID          string // The GitHub App's ID (numeric)
	AppSlug        string // The GitHub App's URL-friendly name
	ClientID       string // The GitHub App's client ID (e.g., Iv1.xxx)
	ClientSecret   string // The GitHub App's client secret
	PrivateKey     string // The GitHub App's private key content
	PrivateKeyPath string // Path to the GitHub App's private key file
	GithubHost     string // GHES host URL
	ServerURL      string // This proxy server's URL
}

// NewHandler creates a new auth handler with the given configuration
func NewHandler(config Config) *Handler {
	return &Handler{
		config: config,
	}
}

// GetServerURL returns the server URL
func (h *Handler) GetServerURL() string {
	return h.config.ServerURL
}

// GetClientID returns the client ID
func (h *Handler) GetClientID() string {
	return h.config.ClientID
}

// IsValidClientID checks if a given client ID matches our configured one
// Handles both full form (Iv1.xxx) and short form
func (h *Handler) IsValidClientID(clientID string) bool {
	configID := h.config.ClientID
	
	// If the given ID is already the full form and matches exactly
	if clientID == configID {
		return true
	}
	
	// If the config ID starts with "Iv1." and the given ID matches the part after it
	if strings.HasPrefix(configID, "Iv1.") && clientID == strings.TrimPrefix(configID, "Iv1.") {
		return true
	}
	
	return false
}

// Token handles the token endpoint
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	log.Printf("Token handler called with method: %s", r.Method)
	log.Printf("Token request headers: %v", r.Header)

	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code": -32601,
				"message": "Method not allowed",
			},
		})
		return
	}

	contentType := r.Header.Get("Content-Type")
	
	// Handle VS Code's OAuth token exchange (form data)
	log.Printf("[DEBUG] Token endpoint hit with content type: %s", contentType)
	
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		log.Printf("[DEBUG] Processing form-encoded token request")
		if err := r.ParseForm(); err != nil {
			log.Printf("[ERROR] Error parsing form: %v", err)
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		
		// Log all form values for debugging
		for key, values := range r.Form {
			log.Printf("[DEBUG] Form value %s: %v", key, values)
		}
		
		code := r.FormValue("code")
		redirectURI := r.FormValue("redirect_uri")
		codeVerifier := r.FormValue("code_verifier")
		grantType := r.FormValue("grant_type")
		
		log.Printf("OAuth token request - code: %v, redirect_uri: %s, grant_type: %s",
			code != "", redirectURI, grantType)
		
		if grantType != "authorization_code" {
			log.Printf("Unsupported grant type: %s", grantType)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "unsupported_grant_type",
				"error_description": "Only authorization_code grant type is supported",
			})
			return
		}

		// Get state from form data
		state := r.FormValue("state")

		// If we have a code verifier, verify it matches stored challenge
		if codeVerifier != "" && state != "" {
			challenge := session.PopState(state + "_cc")
			method := session.PopState(state + "_ccm")
			
			if challenge == "" || method == "" {
				log.Printf("No stored PKCE data found for state: %s", state)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "invalid_request",
					"error_description": "Invalid PKCE state",
				})
				return
			}
		}

		// Exchange code for access token
		tokenURL := fmt.Sprintf("%s/login/oauth/access_token", h.config.GithubHost)
		log.Printf("[DEBUG] Token exchange URL: %s", tokenURL)
		
		tokenData := map[string]interface{}{
			"client_id": h.config.ClientID,
			"client_secret": h.config.ClientSecret,  // Add client secret for GitHub App
			"code": code,
			"redirect_uri": redirectURI,
		}
		if codeVerifier != "" {
			tokenData["code_verifier"] = codeVerifier
		}
		
		log.Printf("[DEBUG] Token exchange request data: %+v", tokenData)
		
		// Log GitHub configuration
		log.Printf("[DEBUG] Using GitHub host: %s", h.config.GithubHost)
		log.Printf("[DEBUG] Using client ID: %s", h.config.ClientID)
		log.Printf("[DEBUG] Client secret present: %v", h.config.ClientSecret != "")

		jsonData, err := json.Marshal(tokenData)
		if err != nil {
			log.Printf("Failed to marshal token request: %v", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "server_error",
				"error_description": "Internal server error",
			})
			return
		}

		req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer(jsonData))
		if err != nil {
			log.Printf("Failed to create token request: %v", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "server_error",
				"error_description": "Internal server error",
			})
			return
		}

		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Token request failed: %v", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "server_error",
				"error_description": "Failed to exchange code for token",
			})
			return
		}
		defer resp.Body.Close()

		var oauthResp struct {
			AccessToken string `json:"access_token"`
			TokenType  string `json:"token_type"`
			Scope     string `json:"scope"`
		}
		var rawResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&rawResp); err != nil {
			log.Printf("[ERROR] Failed to decode token response: %v", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "server_error",
				"error_description": "Invalid token response",
			})
			return
		}

		log.Printf("[DEBUG] Raw token response from GitHub: %+v", rawResp)

		if errMsg, ok := rawResp["error"].(string); ok {
			log.Printf("[ERROR] GitHub returned error: %s - %s", errMsg, rawResp["error_description"])
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": errMsg,
				"error_description": rawResp["error_description"],
			})
			return
		}

		oauthResp.AccessToken = rawResp["access_token"].(string)
		if scope, ok := rawResp["scope"].(string); ok {
			oauthResp.Scope = scope
		}
		if tokenType, ok := rawResp["token_type"].(string); ok {
			oauthResp.TokenType = tokenType
		}

		log.Printf("[DEBUG] Successfully exchanged code for token with scope: %s", oauthResp.Scope)

		// Create a session with the token
		sessionID, err := session.Create(oauthResp.AccessToken, redirectURI)
		if err != nil {
			log.Printf("[ERROR] Failed to create session: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Set session cookie with broader compatibility
		cookie := &http.Cookie{
			Name:     session.SessionCookie,
			Value:    sessionID,
			Path:     "/",  // Covers both / and /? paths
			HttpOnly: true,
			Secure:   strings.HasPrefix(h.config.ServerURL, "https"),  // Set based on protocol
			SameSite: http.SameSiteLaxMode,
			MaxAge:   86400, // 24 hours
		}
		http.SetCookie(w, cookie)
		log.Printf("[DEBUG] Set session cookie: name=%s, path=/, sessionID=%s", session.SessionCookie, sessionID)

		log.Printf("[DEBUG] Created session %s with token for URI %s", sessionID, redirectURI)

		// For VS Code, return the token directly
		response := map[string]interface{}{
			"access_token": oauthResp.AccessToken,
			"token_type":   "Bearer",  // Always use Bearer
			"scope":        oauthResp.Scope,
		}
		log.Printf("[DEBUG] VS Code token request details:")
		log.Printf("  Request URI: %s", r.RequestURI)
		log.Printf("  User-Agent: %s", r.UserAgent())
		log.Printf("  Code: %s...", code[:10])
		log.Printf("  Redirect URI: %s", redirectURI)
		log.Printf("  Grant Type: %s", grantType)
		log.Printf("  Response: access_token=%s***, type=%s, scope=%s", 
			oauthResp.AccessToken[:10], response["token_type"], response["scope"])
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("[ERROR] Error encoding token response: %v", err)
		}
		return
	}
	
	// Handle JSON-RPC style token requests
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding JSON request: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code": -32700,
				"message": "Invalid JSON",
			},
		})
		return
	}
	
	// Generate JWT for app authentication
	jwt, err := h.generateJWT()
	if err != nil {
		log.Printf("JWT generation failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code": -32001,
				"message": "Failed to generate app authentication",
			},
		})
		return
	}

	// Extract parameters
	var installationID, redirectURI string
	if params, ok := req["params"].(map[string]interface{}); ok {
		installationID, _ = params["installation_id"].(string)
		redirectURI, _ = params["redirect_uri"].(string)
	}

	// Validate installation ID
	installations, err := h.getInstallations(jwt)
	if err != nil {
		log.Printf("Failed to get installations: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code": -32001,
				"message": "Failed to validate installation",
			},
		})
		return
	}

	validInstallation := false
	var installationDetails map[string]interface{}
	for _, installation := range installations {
		if id, ok := installation["id"].(float64); ok && fmt.Sprintf("%.0f", id) == installationID {
			validInstallation = true
			installationDetails = installation
			break
		}
	}

	if !validInstallation || installationID == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code": -32602,
				"message": "Invalid installation ID",
			},
		})
		return
	}

	// Get installation token
	token, err := h.getInstallationToken(jwt, installationID)
	if err != nil {
		log.Printf("Installation token exchange failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code": -32001,
				"message": "Installation token exchange failed",
			},
		})
		return
	}

	// Create session
	sessionID, err := session.Create(token, redirectURI)
	if err != nil {
		log.Printf("Session creation failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code": -32603,
				"message": "Internal server error",
			},
		})
		return
	}

	sess := session.Get(sessionID)
	if sess == nil {
		log.Printf("Failed to retrieve created session: %s", sessionID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code": -32603,
				"message": "Session creation failed",
			},
		})
		return
	}

	// Build response with complete GitHub App context
	response := map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"installation_id": installationID,
		"permissions":  installationDetails["permissions"],
		"repository_selection": installationDetails["repository_selection"],
	}

	// Add account information
	if account, ok := installationDetails["account"].(map[string]interface{}); ok {
		response["account"] = account
	}

	// Set session cookie for browser flows
	if !strings.Contains(redirectURI, "127.0.0.1:33418") && 
	   !strings.Contains(redirectURI, "localhost:33418") {
		cookie := &http.Cookie{
			Name:     session.SessionCookie,
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding token response: %v", err)
	}
}