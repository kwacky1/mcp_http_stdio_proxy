package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/kwacky1/mcp_http_stdio_proxy/internal/session"
)

// Global mutex for STDIO operations
var mu sync.Mutex

type ProxyServer struct {
	botToken  string
	serverURL string
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	cmdMutex  sync.Mutex
}

func (p *ProxyServer) startMCPServer(token string) error {
	p.cmdMutex.Lock()
	defer p.cmdMutex.Unlock()

	// Cleanup any existing process
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Kill()
		// Wait for process to finish
		p.cmd.Wait()
	}
	if p.stdin != nil {
		p.stdin.Close()
	}
	if p.stdout != nil {
		p.stdout.Close()
	}

	// Start new MCP server process with stdio parameter
	cmd := exec.Command("/home/infra-admin/github-mcp-server/github-mcp-server", "stdio")
	cmd.Env = append(os.Environ(), fmt.Sprintf("GITHUB_PERSONAL_ACCESS_TOKEN=%s", token))

	// Setup pipes
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		stderr.Close()
		return fmt.Errorf("failed to create stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stderr.Close()
		stdin.Close()
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		stderr.Close()
		stdin.Close()
		stdout.Close()
		return fmt.Errorf("failed to start MCP server: %v", err)
	}

	p.cmd = cmd
	p.stdin = stdin
	p.stdout = stdout

	// Monitor stderr in background
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			log.Printf("[MCP stderr] %s", scanner.Text())
		}
	}()

	// Monitor process in background
	go func() {
		if err := cmd.Wait(); err != nil && err.Error() != "signal: killed" {
			log.Printf("[WARN] MCP server process exited unexpectedly: %v", err)
		}
	}()

	// Initialize the server
	initReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"mode": "stdio",
			"clientInfo": map[string]interface{}{
				"name":    "MCP HTTP STDIO Proxy",
				"version": "1.0.0",
			},
		},
	}

	// Wait for server startup and clear any pending output
	time.Sleep(500 * time.Millisecond)
	reader := bufio.NewReader(stdout)
	for {
		if reader, ok := stdout.(interface{ Buffered() int }); !ok || reader.Buffered() == 0 {
			break
		}
		if _, err := reader.ReadString('\n'); err != nil {
			break
		}
	}

	// Send initialize request
	initReqBytes, _ := json.Marshal(initReq)
	if _, err := stdin.Write(append(initReqBytes, '\n')); err != nil {
		return fmt.Errorf("failed to send initialize request: %v", err)
	}

	// Read response with retries
	var initRespBytes []byte
	var lastErr error
	for retries := 0; retries < 3; retries++ {
		respChan := make(chan []byte, 1)
		errChan := make(chan error, 1)

		go func() {
			if bytes, err := reader.ReadBytes('\n'); err != nil {
				errChan <- fmt.Errorf("failed to read initialize response: %v", err)
			} else {
				respChan <- bytes
			}
		}()

		select {
		case resp := <-respChan:
			initRespBytes = resp
			lastErr = nil
			break
		case err := <-errChan:
			lastErr = err
			time.Sleep(time.Second)
		case <-time.After(2 * time.Second):
			lastErr = fmt.Errorf("timeout waiting for initialize response")
		}

		if lastErr == nil {
			break
		}
	}

	if lastErr != nil {
		return fmt.Errorf("failed to initialize after retries: %v", lastErr)
	}

	// Parse and validate response
	var initResp map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(initRespBytes), &initResp); err != nil {
		return fmt.Errorf("failed to parse initialize response: %v", err)
	}

	if errObj, hasError := initResp["error"]; hasError {
		return fmt.Errorf("server initialization failed: %v", errObj)
	}
	return nil
}

func New(botToken string, serverURL string) *ProxyServer {
	server := &ProxyServer{
		botToken:  botToken,
		serverURL: serverURL,
	}

	// Start initial MCP server process with bot token
	if err := server.startMCPServer(botToken); err != nil {
		log.Fatalf("Failed to start initial MCP server: %v", err)
	}

	return server
}

func (p *ProxyServer) Cleanup() {
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Kill()
	}
	if p.stdin != nil {
		p.stdin.Close()
	}
	if p.stdout != nil {
		p.stdout.Close()
	}
}

func (p *ProxyServer) ProxyMCP(w http.ResponseWriter, r *http.Request, userToken, botToken string) {
	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request", http.StatusInternalServerError)
		return
	}
	r.Body.Close()

	// Parse request to check for method name
	var request struct {
		JSONRPC string      `json:"jsonrpc"`
		ID      int         `json:"id"`
		Method  string      `json:"method"`
		Params  interface{} `json:"params"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		log.Printf("[ERROR] Error parsing JSON-RPC request: %v", err)
		http.Error(w, "Invalid JSON-RPC request", http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Received RPC method: %s (ID: %d)", request.Method, request.ID)

	// Try to get user token from Authorization header or session cookie
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		userToken = strings.TrimPrefix(authHeader, "Bearer ")
	} else if cookie, err := r.Cookie(session.SessionCookie); err == nil {
		if sess := session.Get(cookie.Value); sess != nil {
			userToken = sess.AccessToken
		}
	}
	
	// Handle special methods that don't need proxying
	switch request.Method {
	case "initialize":
		log.Printf("[INFO] Handling initialization request")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      request.ID,
			"result": map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"serverInfo": map[string]interface{}{
					"name":    "MCP HTTP STDIO Proxy",
					"version": "1.0.0",
				},
				"capabilities": map[string]interface{}{
					"roots": map[string]interface{}{
						"listChanged": true,
					},
					"tools": map[string]interface{}{
						"listSupport": true,
						"invocation": true,
					},
					"sampling":    map[string]interface{}{},
					"elicitation": map[string]interface{}{},
				},
			},
		})
		return
	case "notifications/initialized":
		log.Printf("[INFO] Handling notification")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"result":  nil,
		})
		return
	}
	
	// Determine method name and if auth is required
	methodName := request.Method
	if request.Method == "tools/call" {
		if params, ok := request.Params.(map[string]interface{}); ok {
			if name, ok := params["name"].(string); ok {
				methodName = name
			}
		}
	}

	// Check if request requires authentication
	noAuthMethods := map[string]bool{
		"initialize":              true,
		"notifications/initialized": true,
		"tools/list":              true,
	}
	needsAuth := !noAuthMethods[methodName]

	// For operations requiring auth, ensure we have a user token
	if needsAuth && userToken == "" {
		log.Printf("[INFO] No valid auth token found, initiating auth flow for %s", methodName)

		// If we still don't have a token, initiate auth flow
		if userToken == "" {
			// Get the actual tool/method name that needs auth
			methodName := request.Method
			if request.Method == "tools/call" {
				if params, ok := request.Params.(map[string]interface{}); ok {
					if name, ok := params["name"].(string); ok {
						methodName = name
					}
				}
			}
			
			log.Printf("[INFO] No valid auth token found, initiating auth flow for %s", methodName)
			
			// VS Code expects a specific error response format for auth
			w.Header().Set("Content-Type", "application/json")
			authError := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      request.ID,
				"error": map[string]interface{}{
					"code":    -32001,
					"message": "Authorization required",
					"data": map[string]interface{}{
						"providerId": "github",
						"providerUrl": p.serverURL + "/.well-known/oauth-authorization-server",
						"scopes":     []string{"user", "repo", "read:org"},
					},
				},
			}
			log.Printf("[DEBUG] Sending auth error response: %+v", authError)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(authError)
			return
		}
	}

	// Use bot token for non-auth operations, otherwise require user token
	if !needsAuth {
		userToken = botToken
	} else if userToken == "" {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	// Restart the server if using a different token
	if p.cmd != nil && userToken != p.botToken {
		if err := p.startMCPServer(userToken); err != nil {
			log.Printf("[ERROR] Failed to restart MCP server: %v", err)
			http.Error(w, "Failed to proxy request", http.StatusInternalServerError)
			return
		}
		p.botToken = userToken
	}

	// Lock for STDIO operations
	mu.Lock()
	defer mu.Unlock()

	// Try to write request, restart process if pipe is broken
	if _, err = p.stdin.Write(append(body, '\n')); err != nil {
		if err := p.startMCPServer(userToken); err != nil {
			log.Printf("[ERROR] Failed to restart MCP server: %v", err)
			http.Error(w, "Failed to proxy request", http.StatusInternalServerError)
			return
		}
		// Retry write after restart
		if _, err := p.stdin.Write(append(body, '\n')); err != nil {
			log.Printf("[ERROR] Failed to write to STDIN after restart: %v", err)
			http.Error(w, "Failed to proxy request", http.StatusInternalServerError)
			return
		}
	}

	// Read response from STDOUT with timeout
	reader := bufio.NewReader(p.stdout)
	respChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		if bytes, err := reader.ReadBytes('\n'); err != nil {
			errChan <- err
		} else {
			respChan <- bytes
		}
	}()

	var respBytes []byte
	select {
	case respBytes = <-respChan:
	case err := <-errChan:
		log.Printf("[ERROR] Failed to read from STDOUT: %v", err)
		http.Error(w, "Failed to read proxy response", http.StatusInternalServerError)
		return
	case <-time.After(10 * time.Second):
		log.Printf("[ERROR] Timeout reading response from MCP server")
		http.Error(w, "Timeout reading proxy response", http.StatusGatewayTimeout)
		return
	}

	// Validate JSON response
	trimmedResp := bytes.TrimSpace(respBytes)
	var jsonResp map[string]interface{}
	if err := json.Unmarshal(trimmedResp, &jsonResp); err != nil {
		log.Printf("[ERROR] Invalid JSON response: %v", err)
		http.Error(w, "Invalid response from proxy", http.StatusInternalServerError)
		return
	}

	// Return response
	w.Header().Set("Content-Type", "application/json")
	w.Write(trimmedResp)
}