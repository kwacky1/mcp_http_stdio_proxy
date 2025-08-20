package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kwacky1/mcp_http_stdio_proxy/internal/session"
)

// Handler manages GitHub App authentication and OAuth flows
type Handler struct {
	config Config
	privateKeyMu sync.RWMutex
	parsedPrivateKey *rsa.PrivateKey
}

// Config holds the configuration for the auth handler
type Config struct {
	AppID          string
	AppSlug        string
	ClientID       string
	ClientSecret   string
	PrivateKey     string
	PrivateKeyPath string
	GithubHost     string
	ServerURL      string
}

// NewHandler creates a new auth handler with the given configuration
func NewHandler(config Config) *Handler {
	return &Handler{
		config: config,
	}
}

// getPrivateKey returns the parsed RSA private key, either from cache or by parsing it
func (h *Handler) getPrivateKey() (*rsa.PrivateKey, error) {
	h.privateKeyMu.RLock()
	if h.parsedPrivateKey != nil {
		defer h.privateKeyMu.RUnlock()
		return h.parsedPrivateKey, nil
	}
	h.privateKeyMu.RUnlock()

	// Lock for writing
	h.privateKeyMu.Lock()
	defer h.privateKeyMu.Unlock()

	// Check again in case another goroutine parsed it
	if h.parsedPrivateKey != nil {
		return h.parsedPrivateKey, nil
	}

	var pemBytes []byte
	var err error

	// Try loading from environment variable first
	if h.config.PrivateKey != "" {
		pemBytes = []byte(h.config.PrivateKey)
	} else if h.config.PrivateKeyPath != "" {
		// Fall back to loading from file
		pemBytes, err = os.ReadFile(h.config.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %v", err)
		}
	} else {
		return nil, fmt.Errorf("no private key provided")
	}

	// Parse PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	h.parsedPrivateKey = privateKey
	return privateKey, nil
}

// generateJWT creates a new JWT token for GitHub App authentication
func (h *Handler) generateJWT() (string, error) {
	// Get private key
	privateKey, err := h.getPrivateKey()
	if err != nil {
		return "", fmt.Errorf("failed to get private key: %v", err)
	}

	// Create token with claims
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": h.config.AppID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign the token
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return signedToken, nil
}

// OpenIDConfig handles the OpenID configuration endpoint
func (h *Handler) OpenIDConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"issuer":                   h.config.ServerURL,
		"authorization_endpoint":    h.config.ServerURL + "/oauth/authorize",
		"token_endpoint":           h.config.ServerURL + "/oauth/token",
		"userinfo_endpoint":        h.config.ServerURL + "/oauth/userinfo",
		"scopes_supported": []string{
			"repo", "repo:status", "repo_deployment", "public_repo", "repo:invite",
			"security_events", "admin:repo_hook", "write:repo_hook", "read:repo_hook",
			"admin:org", "write:org", "read:org", "admin:public_key",
			"write:public_key", "read:public_key", "admin:org_hook",
			"gist", "notifications", "user", "delete_repo", "write:discussion",
			"read:discussion", "write:packages", "read:packages", "delete:packages",
			"admin:gpg_key", "write:gpg_key", "read:gpg_key", "workflow",
		},
		"response_types_supported": []string{"code"},
		"grant_types_supported":    []string{"authorization_code", "refresh_token"},
		"registration_endpoint":    h.config.ServerURL + "/register",
		"code_challenge_methods_supported": []string{"S256"},
		"service_documentation":    h.config.GithubHost + "/apps/" + h.config.AppSlug,
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// Register handles the registration endpoint
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Get GitHub App information using JWT
	jwt, err := h.generateJWT()
	if err != nil {
		log.Printf("Error generating JWT: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get app details from GitHub
	appDetailsURL := fmt.Sprintf("%s/api/v3/app", h.config.GithubHost)
	req, _ := http.NewRequest("GET", appDetailsURL, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching app details: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var appDetails struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		HTMLURL     string   `json:"html_url"`
		Permissions struct {
			Actions       string `json:"actions"`
			Contents     string `json:"contents"`
			Issues       string `json:"issues"`
			Metadata     string `json:"metadata"`
			PullRequests string `json:"pull_requests"`
		} `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&appDetails); err != nil {
		log.Printf("Error parsing app details: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	registration := map[string]interface{}{
		"client_id": h.config.ClientID,
		"client_secret": h.config.ClientSecret,
		"redirect_uris": []string{
			"https://insiders.vscode.dev/redirect",
			"https://vscode.dev/redirect",
			"http://localhost/",
			"http://127.0.0.1/",
			"http://localhost:33418/",
			"http://127.0.0.1:33418/",
			"vscode-insiders://vscode.dev/",
			"vscode://vscode.dev/",
		},
		"application_type": "web",
		"token_endpoint_auth_method": "client_secret_post",
		"grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"},
		"client_name": appDetails.Name,
		"client_uri": appDetails.HTMLURL,
		"scope": "repo,user",
		"software_id": "github-app:" + h.config.AppID,
		"software_version": "1.0.0",
		"app_permissions": appDetails.Permissions,
	}

	json.NewEncoder(w).Encode(registration)
}

// Authorize handles the authorization endpoint
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	// Extract authorization request parameters
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")
	clientID := r.URL.Query().Get("client_id")
	responseType := r.URL.Query().Get("response_type")
	scope := r.URL.Query().Get("scope")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	
	log.Printf("Authorization request received - state: %s, redirect_uri: %s, client_id: %s, response_type: %s",
		state, redirectURI, clientID, responseType)

	// Validate required parameters
	if state == "" {
		http.Error(w, "Missing required parameter: state", http.StatusBadRequest)
		return
	}

	// Normalize the redirect URI
	if redirectURI == "" {
		redirectURI = h.config.ServerURL + "/app/installations/callback"
	}

	// Check for VS Code client flow
	isVSCodeFlow := strings.Contains(redirectURI, "localhost") ||
		strings.Contains(redirectURI, "127.0.0.1") ||
		strings.Contains(redirectURI, "vscode://") ||
		strings.Contains(redirectURI, "vscode-insiders://")
		
	// Set up base OAuth parameters
	q := url.Values{}
	q.Set("client_id", h.config.ClientID)
	q.Set("state", state)
	
	// Store state info
	stateStore := map[string]interface{}{
		"redirect_uri": redirectURI,
		"is_vscode": isVSCodeFlow,
		"code_challenge": codeChallenge,
		"code_challenge_method": codeChallengeMethod,
		"scope": scope,
	}
	stateBytes, _ := json.Marshal(stateStore)
	session.StoreState(state, string(stateBytes))

	// Configure OAuth flow based on client type
	if isVSCodeFlow {
		q.Set("redirect_uri", redirectURI)
	} else {
		q.Set("redirect_uri", h.config.ServerURL+"/oauth/callback")
	}

	// Set required GitHub App OAuth scopes
	requestedScopes := []string{"repo", "user"}
	if scope != "" {
		scopes := strings.Split(scope, " ")
		requestedScopes = append(requestedScopes, scopes...)
	}
	q.Set("scope", strings.Join(requestedScopes, " "))

	// Pass through optional parameters
	if login := r.URL.Query().Get("login"); login != "" {
		q.Set("login", login)
	}
	if allowSignup := r.URL.Query().Get("allow_signup"); allowSignup != "" {
		q.Set("allow_signup", allowSignup)
	}
	if prompt := r.URL.Query().Get("prompt"); prompt != "" {
		q.Set("prompt", prompt)
	}

	// Add PKCE challenge if provided
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		if codeChallengeMethod != "" {
			q.Set("code_challenge_method", codeChallengeMethod)
		} else {
			q.Set("code_challenge_method", "S256")
		}
	}

	// Build and validate authorization URL
	authURL := fmt.Sprintf("%s/login/oauth/authorize?%s", h.config.GithubHost, q.Encode())
	if _, err := url.Parse(authURL); err != nil {
		log.Printf("Error constructing authorization URL: %v", err)
		http.Error(w, "Invalid authorization URL", http.StatusInternalServerError)
		return
	}
	
	log.Printf("Redirecting to GitHub authorization URL: %s", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// exchangeCodeForToken exchanges an authorization code for an access token
func (h *Handler) exchangeCodeForToken(code string, codeVerifier string, redirectURI string) (string, string, error) {
	tokenURL := h.config.GithubHost + "/login/oauth/access_token"
	
	data := url.Values{}
	data.Set("client_id", h.config.ClientID)
	data.Set("client_secret", h.config.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-GitHub-Client-Id", h.config.ClientID)
	req.Header.Set("User-Agent", fmt.Sprintf("GitHub-App/%s", h.config.AppSlug))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("token exchange failed: %s - %s", resp.Status, string(body))
	}

	var res struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope      string `json:"scope"`
		Error      string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorURI    string `json:"error_uri"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", "", fmt.Errorf("parse response: %v", err)
	}

	if res.Error != "" {
		errMsg := res.Error
		if res.ErrorDescription != "" {
			errMsg += ": " + res.ErrorDescription
		}
		return "", "", fmt.Errorf("oauth error: %s", errMsg)
	}

	if res.AccessToken == "" {
		return "", "", fmt.Errorf("no access token in response: %s", string(body))
	}

	// Verify token and get associated app installations
	installations, err := h.getUserInstallations(res.AccessToken)
	if err != nil {
		log.Printf("Warning: Failed to get user installations: %v", err)
	} else {
		log.Printf("Found %d installations for user token", len(installations))
	}

	return res.AccessToken, res.Scope, nil
}

// Callback handles the OAuth callback
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	log.Printf("Callback received with full URL: %s", r.URL.String())
	
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	installationID := r.URL.Query().Get("installation_id")
	error := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")
	
	log.Printf("Callback parameters - state: %s, code: %v, installation_id: %s, error: %s",
		state, code != "", installationID, error)
		
	// Handle OAuth errors
	if error != "" {
		log.Printf("OAuth error received: %s - %s", error, errorDescription)
		http.Error(w, fmt.Sprintf("Authentication failed: %s", errorDescription), http.StatusBadRequest)
		return
	}

	// Validate and retrieve state
	storedState := session.PopState(state)
	if storedState == "" {
		log.Printf("No stored state found for: %s - potential CSRF attempt", state)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Parse stored state
	var stateData struct {
		RedirectURI         string `json:"redirect_uri"`
		IsVSCode           bool   `json:"is_vscode"`
		CodeChallenge      string `json:"code_challenge"`
		CodeChallengeMethod string `json:"code_challenge_method"`
		Scope              string `json:"scope"`
	}
	if err := json.Unmarshal([]byte(storedState), &stateData); err != nil {
		log.Printf("Error parsing stored state: %v", err)
		http.Error(w, "Invalid state data", http.StatusBadRequest)
		return
	}

	log.Printf("Retrieved state data - redirect_uri: %s, is_vscode: %v",
		stateData.RedirectURI, stateData.IsVSCode)

	// Handle OAuth code exchange
	if code != "" {
		log.Printf("Exchanging OAuth code for access token")
		codeVerifier := r.URL.Query().Get("code_verifier")
		token, scope, err := h.exchangeCodeForToken(code, codeVerifier, stateData.RedirectURI)
		if err != nil {
			log.Printf("Token exchange failed: %v", err)
			http.Error(w, "Failed to complete authentication", http.StatusInternalServerError)
			return
		}
		
		log.Printf("Token exchange successful - scope: %s", scope)

		// Get user installations
		installations, err := h.getUserInstallations(token)
		if err != nil {
			log.Printf("Warning: Failed to get user installations: %v", err)
		}

		// Get user info for the session
		userInfo, err := h.getUserInfo(token)
		if err != nil {
			log.Printf("Warning: Failed to get user info: %v", err)
		}

		// Create session with installations
		sessionID, err := session.Create(token, stateData.RedirectURI)
		if err != nil {
			log.Printf("Session creation failed: %v", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		// Update session with installations
		sess := session.Get(sessionID)
		if sess != nil {
			for _, inst := range installations {
				account, _ := inst["account"].(map[string]interface{})
				accountName, _ := account["login"].(string)
				permissions, _ := inst["permissions"].(map[string]interface{})
				id, _ := inst["id"].(float64)

				sess.Installations = append(sess.Installations, session.Installation{
					ID:          int64(id),
					Account:     accountName,
					Permissions: permissions,
				})
			}

			if userInfo != nil {
				if accountType, ok := userInfo["type"].(string); ok {
					sess.AccountType = accountType
				}
				if accountLogin, ok := userInfo["login"].(string); ok {
					sess.AccountLogin = accountLogin
				}
			}
		}

		// Set session cookie for browser flows
		if !stateData.IsVSCode {
			cookie := &http.Cookie{
				Name:     session.SessionCookie,
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
				SameSite: http.SameSiteLaxMode,
			}
			http.SetCookie(w, cookie)
			log.Printf("Set session cookie for browser flow")
		}
	}

	// Build final redirect URI with parameters
	finalURI := stateData.RedirectURI
	params := url.Values{}

	// Add any additional parameters
	if code != "" {
		params.Set("code", code)
	}
	if state != "" {
		params.Set("state", state)
	}
	if installationID != "" {
		params.Set("installation_id", installationID)
	}

	// Construct redirect URL with parameters
	if len(params) > 0 {
		if strings.Contains(finalURI, "?") {
			finalURI += "&" + params.Encode()
		} else {
			finalURI += "?" + params.Encode()
		}
	}

	log.Printf("Redirecting to final URI: %s", finalURI)
	http.Redirect(w, r, finalURI, http.StatusFound)
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
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			log.Printf("Error parsing form: %v", err)
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		
		code := r.FormValue("code")
		redirectURI := r.FormValue("redirect_uri")
		codeVerifier := r.FormValue("code_verifier")
		grantType := r.FormValue("grant_type")
		
		log.Printf("OAuth token request - code: %v, redirect_uri: %s, grant_type: %s",
			code != "", redirectURI, grantType)
		
		var token, scope string
		var err error
		
		switch grantType {
		case "authorization_code":
			token, scope, err = h.exchangeCodeForToken(code, codeVerifier, redirectURI)
			if err != nil {
				log.Printf("Token exchange failed: %v", err)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "invalid_grant",
					"error_description": err.Error(),
				})
				return
			}
		default:
			log.Printf("Unsupported grant type: %s", grantType)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "unsupported_grant_type",
				"error_description": "Only authorization_code grant type is supported",
			})
			return
		}
		
		sessionID, err := session.Create(token, redirectURI)
		if err != nil {
			log.Printf("Session creation failed: %v", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "server_error",
				"error_description": "Failed to create session",
			})
			return
		}
		
		sess := session.Get(sessionID)
		if sess == nil {
			log.Printf("Failed to retrieve created session: %s", sessionID)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "server_error",
				"error_description": "Session creation failed",
			})
			return
		}
		
		// For VS Code, we return the GitHub token directly
		if strings.Contains(redirectURI, "127.0.0.1:33418") ||
		   strings.Contains(redirectURI, "localhost:33418") ||
		   strings.Contains(redirectURI, "vscode://") ||
		   strings.Contains(redirectURI, "vscode-insiders://") {
			response := map[string]interface{}{
				"access_token": token,
				"token_type": "Bearer",
				"scope": scope,
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(response); err != nil {
				log.Printf("Error encoding OAuth response: %v", err)
			}
			return
		}

		// For browser flows, use our session token
		response := map[string]interface{}{
			"access_token": token,
			"token_type": "Bearer",
			"scope": scope,
			"expires_in": 3600,
		}
		
		if len(sess.Installations) > 0 {
			installs := make([]map[string]interface{}, 0)
			for _, inst := range sess.Installations {
				installs = append(installs, map[string]interface{}{
					"id": inst.ID,
					"account": inst.Account,
					"permissions": inst.Permissions,
				})
			}
			response["installations"] = installs
		}
		
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding OAuth response: %v", err)
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

// UserInfo handles the userinfo endpoint
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	sessionID := ""
	cookie, err := r.Cookie(session.SessionCookie)
	if err == nil {
		sessionID = cookie.Value
	}

	sess := session.Get(sessionID)
	if sess == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code": -32001,
				"message": "Not authenticated",
			},
		})
		return
	}

	userInfo, err := h.getUserInfo(sess.AccessToken)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code": -32003,
				"message": "Failed to fetch user info",
				"data": map[string]interface{}{
					"details": err.Error(),
				},
			},
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}