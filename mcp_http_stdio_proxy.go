package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ========== CONFIGURATION ==========

var (
	clientID     = os.Getenv("OAUTH_CLIENT_ID")
	clientSecret = os.Getenv("OAUTH_CLIENT_SECRET")
	ghesURL      = os.Getenv("GITHUB_HOST")
	serverURL    = os.Getenv("MCP_HOST") 
	botToken     = os.Getenv("GITHUB_PERSONAL_ACCESS_TOKEN") // Bot token fallback
)

// ========== IN-MEMORY SESSION STORE ==========

type Session struct {
	AccessToken string
	CreatedAt   time.Time
	RedirectURI string
	UserProxy   *stdioProxy // Add reference to user's MCP server instance
	LastAccess  time.Time   // Track last access time for cleanup
}

const (
	sessionTimeout = 24 * time.Hour // Sessions expire after 24 hours of inactivity
	cleanupInterval = time.Hour     // Run cleanup every hour
)

var (
	sessionStore  = map[string]*Session{}
	sessionMu     sync.Mutex
	sessionCookie = "mcp_session"
)

func createSession(token, redirectURI string) (string, error) {
	id := fmt.Sprintf("%x", time.Now().UnixNano())
	
	// Create new MCP server instance for this user with their token
	userProxy := newStdioProxy(token)
	
	sessionMu.Lock()
	defer sessionMu.Unlock()
	sessionStore[id] = &Session{
		AccessToken: token,
		CreatedAt:   time.Now(),
		RedirectURI: redirectURI,
		UserProxy:   userProxy,
	}
	return id, nil
}
func getSession(id string) *Session {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if session := sessionStore[id]; session != nil {
		session.LastAccess = time.Now()
		return session
	}
	return nil
}

// ========== .env LOADER ==========

func loadEnv(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()
	var env []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		env = append(env, line)
	}
	return env
}

// ========== STATE STORE FOR OAUTH REDIRECT_URI ==========

var (
	stateStore = map[string]string{} // state -> redirect_uri
	stateMu    sync.Mutex
)

func storeState(state, redirectURI string) {
	stateMu.Lock()
	defer stateMu.Unlock()
	stateStore[state] = redirectURI
}
func popState(state string) string {
	stateMu.Lock()
	defer stateMu.Unlock()
	uri := stateStore[state]
	delete(stateStore, state)
	return uri
}

// ========== TOOL AUTHENTICATION MAP ==========
// In production, load this from your MCP stdio server or manifest!
var toolRequiresAuth = map[string]bool{
	"get_me":        true,
	"create_issue":  true,
	"search_repos":  false, // Example: public tool
	// Add other tools here
}

// Helper: Checks if the requested method/tool requires authentication
func toolNeedsAuth(jsonBody []byte) bool {
	var req map[string]interface{}
	_ = json.Unmarshal(jsonBody, &req)
	method, _ := req["method"].(string)
	if method == "tools/call" {
		if params, ok := req["params"].(map[string]interface{}); ok {
			toolName, _ := params["name"].(string)
			return toolRequiresAuth[toolName]
		}
	}
	return false
}

// ========== MCP PROXY TO STDIO SERVER ==========

type stdioProxy struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	mu     sync.Mutex
}

func newStdioProxy(token string) *stdioProxy {
	log.Printf("Creating new stdio proxy with token length: %d", len(token))
	cmd := exec.Command("./github-mcp-server", "stdio")
	
	// Load environment from .env file
	env := loadEnv(".env")
	log.Printf("Loaded env file: %v", env != nil)
	if env != nil {
		// Filter out any existing GITHUB_PERSONAL_ACCESS_TOKEN
		var newEnv []string
		for _, e := range env {
			if !strings.HasPrefix(e, "GITHUB_PERSONAL_ACCESS_TOKEN=") {
				newEnv = append(newEnv, e)
			}
		}
		env = newEnv
	}
	
	// Add the token
	env = append(env, "GITHUB_PERSONAL_ACCESS_TOKEN="+token)
	cmd.Env = append(os.Environ(), env...)
	
	log.Printf("Starting MCP server with authentication")
	
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	// Setup stderr pipe to capture errors
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}
	
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	
	// Start goroutine to read stderr
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("MCP stderr: %s", scanner.Text())
		}
	}()
	
	log.Println("Started github-mcp-server over stdio")
	return &stdioProxy{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReader(stdoutPipe),
	}
}

// restartWithToken restarts the MCP server using the given token
func (p *stdioProxy) restartWithToken(token string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Kill existing process
	if err := p.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("failed to kill existing process: %v", err)
	}
	
	// Start new process with token
	cmd := exec.Command("./github-mcp-server", "stdio")
	env := loadEnv(".env")
	if env != nil {
		// Filter out any existing GITHUB_PERSONAL_ACCESS_TOKEN
		var newEnv []string
		for _, e := range env {
			if !strings.HasPrefix(e, "GITHUB_PERSONAL_ACCESS_TOKEN=") {
				newEnv = append(newEnv, e)
			}
		}
		env = newEnv
	}
	// Add the new token
	env = append(env, "GITHUB_PERSONAL_ACCESS_TOKEN="+token)
	cmd.Env = append(os.Environ(), env...)
	
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %v", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %v", err)
	}
	
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start process: %v", err)
	}
	
	// Update struct fields
	p.cmd = cmd
	p.stdin = stdin
	p.stdout = bufio.NewReader(stdoutPipe)
	
	// Start stderr reader
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("MCP stderr: %s", scanner.Text())
		}
	}()
	
	log.Printf("Restarted MCP server with new token")
	return nil
}

func (p *stdioProxy) cleanup() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd != nil && p.cmd.Process != nil {
		if err := p.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill process: %v", err)
		}
		// Wait for the process to finish
		if err := p.cmd.Wait(); err != nil {
			log.Printf("Process wait error (expected after kill): %v", err)
		}
	}
	
	if p.stdin != nil {
		p.stdin.Close()
	}
	
	return nil
}

func (p *stdioProxy) ProxyMCP(w http.ResponseWriter, r *http.Request, userToken string, botToken string) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	// The body should have been read and passed in through r.Body already
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body in ProxyMCP: %v", err)
		http.Error(w, "Error reading request", http.StatusBadRequest)
		return
	}
	log.Printf("HTTP->STDIO (ProxyMCP): %s", string(body))

	// Parse request once for all uses
	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("Error unmarshaling request: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	needsAuth := toolNeedsAuth(body)
	finalToken := userToken

	if needsAuth && userToken == "" && p != nil {
		// Log all cookies for debugging
		for _, c := range r.Cookies() {
			log.Printf("Found cookie: %s = %s", c.Name, c.Value)
		}
		cookie, err := r.Cookie(sessionCookie)
		log.Printf("Looking for cookie named '%s'. Found: %v, err: %v", sessionCookie, cookie, err)

		// Check for Authorization header
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			log.Printf("Found Bearer token (truncated): %s...", token[:10])
			
			// First try it as a session ID
			if session := getSession(token); session != nil {
				finalToken = session.AccessToken
				log.Printf("Found valid session from Bearer token")
				goto hasToken
			}
			
			// If not a session ID, maybe it's a direct GitHub token
			if strings.HasPrefix(token, "gho_") {
				finalToken = token
				log.Printf("Using Bearer token directly as GitHub token")
				goto hasToken
			}
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp",authorization_uri="`+serverURL+`/oauth/authorize"`)
		log.Printf("Set WWW-Authenticate header in ProxyMCP: %s", w.Header().Get("WWW-Authenticate"))

		// Format error response in JSON-RPC 2.0 format
		errorResp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"], // Use the original request ID
			"error": map[string]interface{}{
				"code":    -32001, // Use JSON-RPC error code range
				"message": "Authentication required",
				"data": map[string]interface{}{
					"type":        "auth",
					"authUri":     serverURL + "/oauth/authorize",
					"retry":       true,
					"retryReason": "Please complete the authentication flow",
					"status":      401, // Include HTTP status for reference
				},
			},
		}
		json.NewEncoder(w).Encode(errorResp)
		return
	}

hasToken:
	if !needsAuth && userToken == "" && botToken != "" {
		finalToken = botToken
	}

	// Always use a copy of the request
	newReq := make(map[string]interface{})
	for k, v := range req {
		newReq[k] = v
	}

	_, hasID := newReq["id"]

	if finalToken != "" {
		
		// Ensure params exists and is a map
		params, ok := newReq["params"].(map[string]interface{})
		if !ok {
			// If params doesn't exist or isn't a map, create a new one
			params = make(map[string]interface{})
			if existing, ok := newReq["params"]; ok {
				// If params exists but isn't a map, preserve it as a value
				params["originalParams"] = existing
			}
		} else {
			// Make a copy of the existing params map
			newParams := make(map[string]interface{})
			for k, v := range params {
				newParams[k] = v
			}
			params = newParams
		}
		
		params["token"] = finalToken
		newReq["params"] = params
		body, _ = json.Marshal(newReq)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Marshal the request to send to stdio
	bodyToWrite, err := json.Marshal(newReq)
	if err != nil {
		log.Printf("Error marshaling request: %v", err)
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
	log.Printf("Writing to stdio: %s", string(bodyToWrite))

	// Write request with proper line ending and flush
	if _, err := p.stdin.Write(append(bodyToWrite, '\n')); err != nil {
		log.Printf("Error writing to stdin: %v", err)
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

	if hasID {
		respLine, _ := p.stdout.ReadBytes('\n')
		log.Printf("STDIO->HTTP: %s", string(respLine))
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes.TrimSpace(respLine))
	} else {
		// Return JSON-RPC response even for requests without ID
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"result":  nil,
		})
	}
}

// ========== OAUTH/OIDC HANDLERS ==========

func openidConfigHandler(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"issuer":                   serverURL,
		"authorization_endpoint":   serverURL + "/oauth/authorize",
		"token_endpoint":           serverURL + "/oauth/token",
		"userinfo_endpoint":        serverURL + "/oauth/userinfo",
		"scopes_supported":         []string{"repo", "read:org", "user"},
		"response_types_supported": []string{"code"},
		"grant_types_supported":    []string{"authorization_code"},
		"registration_endpoint":    serverURL + "/register",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"client_id":     clientID,
		"client_secret": clientSecret,
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
		"token_endpoint_auth_method": "none",
		"application_type":           "native",
	}
	json.NewEncoder(w).Encode(resp)
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = serverURL + "/oauth/callback"
	}

	// For VS Code's direct flow (localhost or protocol handler)
	log.Printf("Authorize request with redirect_uri: %s", redirectURI)
	if strings.Contains(redirectURI, "localhost") || 
	   strings.Contains(redirectURI, "127.0.0.1") ||
	   strings.Contains(redirectURI, "vscode://") ||
	   strings.Contains(redirectURI, "vscode-insiders://") {
		// Pass through all parameters directly to GHES
		q := r.URL.Query()
		q.Set("client_id", clientID) // Only override the client_id
		authURL := fmt.Sprintf("%s/login/oauth/authorize?%s", ghesURL, q.Encode())
		log.Printf("Redirecting to GHES auth URL: %s", authURL)
		http.Redirect(w, r, authURL, http.StatusFound)
		return
	}

	// Legacy flow for other clients
	storeState(state, redirectURI)
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", serverURL + "/oauth/callback") // Use proxy callback
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("response_type", "code")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
	}
	if codeChallengeMethod != "" {
		q.Set("code_challenge_method", codeChallengeMethod)
	}
	authURL := fmt.Sprintf("%s/login/oauth/authorize?%s", ghesURL, q.Encode())
	http.Redirect(w, r, authURL, http.StatusFound)
}

// /oauth/callback handler: This is now only useful for browser-based or legacy flows
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// For VS Code, this should not be used!
	fmt.Fprintf(w, "If you see this page, your client did not provide a localhost or vscode:// redirect URI.")
}

// Exchange authorization code for access token
func exchangeCodeForToken(code string, codeVerifier string, redirectURI string) (string, error) {
	tokenURL := ghesURL + "/login/oauth/access_token"
	
	// Build form data
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	// Create request with form body
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %v", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange failed: %s - %s", resp.Status, string(body))
	}

	// Parse response
	var res struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope      string `json:"scope"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", fmt.Errorf("parse response: %v", err)
	}

	// Check for OAuth error response
	if res.Error != "" {
		return "", fmt.Errorf("oauth error: %s", res.Error)
	}

	if res.AccessToken == "" {
		return "", fmt.Errorf("no access token in response: %s", string(body))
	}

	return res.AccessToken, nil
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Token handler called with method: %s", r.Method)
	log.Printf("Token request headers: %v", r.Header)
	
	// VS Code sends form data for OAuth token exchange
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			log.Printf("Error parsing form: %v", err)
		}
		log.Printf("Token request form values: %v", r.Form)
	}
	
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

	var code, redirectURI, codeVerifier string
	contentType := r.Header.Get("Content-Type")

	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		// Handle OAuth token exchange from VS Code
		code = r.FormValue("code")
		redirectURI = r.FormValue("redirect_uri")
		codeVerifier = r.FormValue("code_verifier")
	} else {
		// Handle JSON-RPC format
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
		
		if params, ok := req["params"].(map[string]interface{}); ok {
			code, _ = params["code"].(string)
			redirectURI, _ = params["redirect_uri"].(string)
			codeVerifier, _ = params["code_verifier"].(string)
		}
	}

	if code == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code": -32602,
				"message": "No code provided",
			},
		})
		return
	}

	token, err := exchangeCodeForToken(code, codeVerifier, redirectURI)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code": -32001,
				"message": "Token exchange failed",
				"data": map[string]interface{}{
					"details": err.Error(),
				},
			},
		})
		return
	}

	log.Printf("Token exchange successful, token length: %d", len(token))
	
	// Create a session with a new MCP server instance for this token
	sessionID, err := createSession(token, redirectURI)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
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
	
	log.Printf("Created session with ID: %s", sessionID)

	// For VS Code OAuth flow, we want to return the actual GitHub token
	// This allows VS Code to use it directly with the GitHub API
	w.Header().Set("Content-Type", "application/json")
	
	response := map[string]interface{}{
		"access_token": token, // Use actual GitHub token instead of session ID
		"token_type":   "Bearer",
		"scope":        "user read:org repo",
		"expires_in":   86400, // 24 hours in seconds
	}

	// Only set cookie and VS Code specific metadata for non-OAuth flows
	if !strings.Contains(redirectURI, "127.0.0.1:33418") && 
	   !strings.Contains(redirectURI, "localhost:33418") {
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
			Domain:   "",
			SameSite: http.SameSiteLaxMode,
		})
		w.Header().Set("Set-Cookie", fmt.Sprintf("%s=%s; Path=/; HttpOnly; SameSite=Lax", sessionCookie, sessionID))
		
		// Add VS Code specific metadata only for non-OAuth flows
		response["account"] = map[string]interface{}{
			"id":    sessionID,
			"label": "GitHub Enterprise",
		}
	}
	
	responseJson, _ := json.Marshal(response)
	log.Printf("Sending token response: %s", string(responseJson))
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding token response: %v", err)
	}
	
	log.Printf("Token response headers: %v", w.Header())
}

func userinfoHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := ""
	cookie, err := r.Cookie(sessionCookie)
	if err == nil {
		sessionID = cookie.Value
	}
	session := getSession(sessionID)
	if session == nil {
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
	req, _ := http.NewRequest("GET", ghesURL+"/api/v3/user", nil)
	req.Header.Set("Authorization", "token "+session.AccessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
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
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

// ========== SESSION CLEANUP ==========

func cleanupSessions() {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	
	now := time.Now()
	for id, session := range sessionStore {
		if now.Sub(session.LastAccess) > sessionTimeout {
			// Clean up the MCP server instance
			if session.UserProxy != nil {
				if err := session.UserProxy.cleanup(); err != nil {
					log.Printf("Error cleaning up MCP server for session %s: %v", id, err)
				}
			}
			// Remove the session
			delete(sessionStore, id)
			log.Printf("Cleaned up expired session: %s", id)
		}
	}
}

func startCleanupRoutine(ctx context.Context) {
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

// ========== MAIN ROUTER ==========

var defaultProxy *stdioProxy

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Create default proxy for initialization with bot token
	if botToken != "" {
		defaultProxy = newStdioProxy(botToken)
		defer defaultProxy.cleanup()
	}
	
	// Start the cleanup routine
	startCleanupRoutine(ctx)

	// Create a new ServeMux to have more control over routing
	mux := http.NewServeMux()

	// Register auth endpoints first to ensure they take precedence
	mux.HandleFunc("/.well-known/openid-configuration", openidConfigHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/oauth/authorize", authorizeHandler)
	mux.HandleFunc("/authorize", authorizeHandler) // Support both paths
	mux.HandleFunc("/oauth/callback", callbackHandler)
	mux.HandleFunc("/oauth/token", tokenHandler)
	mux.HandleFunc("/oauth/userinfo", userinfoHandler)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Ignore GET requests to paths that should be handled by auth endpoints
		if r.Method == "GET" && (
			strings.HasPrefix(r.URL.Path, "/.well-known/") ||
			strings.HasPrefix(r.URL.Path, "/oauth/") ||
			strings.HasPrefix(r.URL.Path, "/authorize") ||
			strings.HasPrefix(r.URL.Path, "/register")) {
			http.NotFound(w, r)
			return
		}
		
		// Handle health check GET requests with JSON-RPC response
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"result": map[string]interface{}{
					"status": "ok",
				},
			})
			return
		}
		
		// Log non-GET requests
		log.Printf("Received request: %s %s", r.Method, r.URL.Path)
		
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading request body: %v", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"error": map[string]interface{}{
					"code": -32700,
					"message": "Error reading request",
				},
			})
			return
		}
		log.Printf("Request body: %s", string(body))
		
		// Parse request
		var req map[string]interface{}
		if err := json.Unmarshal(body, &req); err != nil {
			log.Printf("Error parsing JSON: %v", err)
			if r.Method == "POST" && len(body) == 0 {
				// Empty POST needs a JSON-RPC response
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      nil,
					"result":  nil,
				})
				return
			}
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
		
		method, _ := req["method"].(string)

		// Handle notifications with empty JSON-RPC response
		if strings.HasPrefix(method, "notifications/") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"result":  nil,
			})
			return
		}

		// Always handle initialize and tools/list with a JSON response
		if method == "initialize" || method == "tools/list" {
			if defaultProxy != nil {
				r.Body = io.NopCloser(bytes.NewReader(body))
				defaultProxy.ProxyMCP(w, r, "", botToken)
			} else {
				// Return empty success response
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"result":  map[string]interface{}{},
				})
			}
			return
		}
		
		needsAuth := toolNeedsAuth(body)
		
		// For unauthenticated tools, handle with default proxy
		if !needsAuth {
			if defaultProxy != nil {
				r.Body = io.NopCloser(bytes.NewReader(body))
				defaultProxy.ProxyMCP(w, r, "", botToken)
				return
			}
			// Fallback if no default proxy available
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result":  nil,
			})
			return
		}
		
		// Get session
		sessionID := ""
		cookie, err := r.Cookie(sessionCookie)
		if err == nil {
			sessionID = cookie.Value
			log.Printf("Found session cookie with ID: %s", sessionID)
		} else {
			log.Printf("No session cookie found: %v", err)
		}
		
		var userToken string

		// Check Authorization header for token
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			bearerToken := strings.TrimPrefix(authHeader, "Bearer ")
			log.Printf("Found Bearer token, checking if it's a session ID or GitHub token...")
			
			if strings.HasPrefix(bearerToken, "gho_") {
				// Direct GitHub token
				log.Printf("Found GitHub token, using directly")
				userToken = bearerToken
			} else if session := getSession(bearerToken); session != nil {
				// Session ID
				log.Printf("Bearer token is a valid session ID")
				userToken = session.AccessToken
			}
		}
		
		// Also check for session in cookie if no token found yet
		if userToken == "" && sessionID != "" {
			if session := getSession(sessionID); session != nil {
				userToken = session.AccessToken
			}
		}

		// If we have a token, either from session or direct GitHub token
		if userToken != "" {
			// Create a new proxy for this request if needed
			proxy := defaultProxy
			if strings.HasPrefix(userToken, "gho_") {
				proxy = newStdioProxy(userToken)
				defer proxy.cleanup()
			}
			
			// Reset the body with our parsed request
			r.Body = io.NopCloser(bytes.NewReader(body))
			proxy.ProxyMCP(w, r, userToken, "")
		} else {
			// No valid session, require authentication without creating a new proxy
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp",authorization_uri="`+serverURL+`/oauth/authorize"`)
			w.WriteHeader(http.StatusUnauthorized) // Make sure we send 401
			log.Printf("Set WWW-Authenticate header in main handler: %s", w.Header().Get("WWW-Authenticate"))
			
			// Format error response in JSON-RPC 2.0 format
			errorResp := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"], // Use request ID if present
				"error": map[string]interface{}{
					"code":    -32001, // Use JSON-RPC error code range
					"message": "Authentication required",
					"data": map[string]interface{}{
						"type":        "auth",
						"authUri":     serverURL + "/oauth/authorize",
						"retry":       true,
						"retryReason": "Please complete the authentication flow",
						"status":      401, // Include HTTP status for reference
					},
				},
			}
			json.NewEncoder(w).Encode(errorResp)
		}
	})

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}