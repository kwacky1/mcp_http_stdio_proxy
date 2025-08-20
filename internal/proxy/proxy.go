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
	
	// Set GITHUB_PERSONAL_ACCESS_TOKEN in the environment
	cmd.Env = append(os.Environ(), fmt.Sprintf("GITHUB_PERSONAL_ACCESS_TOKEN=%s", token))
	
	// Setup stderr pipe to capture errors
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

	// Monitor process stderr in background
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			log.Printf("[MCP stderr] %s", scanner.Text())
		}
	}()

	// Monitor process in background
	go func() {
		if err := cmd.Wait(); err != nil {
			if err.Error() != "signal: killed" {
				log.Printf("[WARN] MCP server process exited unexpectedly: %v", err)
			}
		}
	}()

	// Initialize the server by sending an initialize request
	initReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"mode":        "stdio",
			"clientInfo": map[string]interface{}{
				"name":    "MCP HTTP STDIO Proxy",
				"version": "1.0.0",
			},
		},
	}
	
	// Wait a bit for the server to start
	time.Sleep(500 * time.Millisecond)
	
	reader := bufio.NewReader(stdout)
	
	// Check if there's any pending output
	for {
		available := false
		if reader, ok := stdout.(interface{ Buffered() int }); ok {
			available = reader.Buffered() > 0
		}
		
		if !available {
			break
		}
		
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[WARN] Error reading startup output: %v", err)
			}
			break
		}
		log.Printf("[MCP stdout] Startup message: %s", line)
	}
	
	log.Printf("[DEBUG] Sending initialize request")
	
	// Now send the initialize request
	initReqBytes, _ := json.Marshal(initReq)
	if _, err := stdin.Write(append(initReqBytes, '\n')); err != nil {
		return fmt.Errorf("failed to send initialize request: %v", err)
	}

	// Read response with multiple retries
	var initRespBytes []byte
	var lastErr error
	
	for retries := 0; retries < 3; retries++ {
		respChan := make(chan []byte, 1)
		errChan := make(chan error, 1)
		
		go func() {
			initRespBytes, err := reader.ReadBytes('\n')
			if err != nil {
				errChan <- fmt.Errorf("failed to read initialize response: %v", err)
				return
			}
			respChan <- initRespBytes
		}()
		
		// Wait for response with timeout
		select {
		case resp := <-respChan:
			initRespBytes = resp
			lastErr = nil
			break
		case err := <-errChan:
			lastErr = err
			log.Printf("[WARN] Initialize attempt %d failed: %v", retries+1, err)
			time.Sleep(time.Second) // Wait before retry
			continue
		case <-time.After(2 * time.Second):
			lastErr = fmt.Errorf("timeout waiting for initialize response")
			log.Printf("[WARN] Initialize attempt %d timed out", retries+1)
			continue
		}
		
		if lastErr == nil {
			break
		}
	}
	
	if lastErr != nil {
		return fmt.Errorf("failed to initialize after retries: %v", lastErr)
	}

	// Try to parse the response as JSON
	trimmedResp := bytes.TrimSpace(initRespBytes)
	log.Printf("[DEBUG] Initialize response: %q", string(trimmedResp))
	
	var initResp map[string]interface{}
	if err := json.Unmarshal(trimmedResp, &initResp); err != nil {
		return fmt.Errorf("failed to parse initialize response: %v (raw: %q)", err, string(initRespBytes))
	}

	// Check for initialization error
	if errObj, hasError := initResp["error"]; hasError {
		return fmt.Errorf("server initialization failed: %v", errObj)
	}
	
	log.Printf("[INFO] Server initialized successfully")
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

	// Debug logging
	log.Printf("[DEBUG] Full request: %s", string(body))
	log.Printf("[INFO] Received RPC method: %s (ID: %d)", request.Method, request.ID)
	log.Printf("[DEBUG] User token present: %v", userToken != "")
	
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
	
	// Check if request requires authentication - default to requiring auth
	needsAuth := true
	methodName := request.Method

	if request.Method == "tools/call" {
		if params, ok := request.Params.(map[string]interface{}); ok {
			if name, ok := params["name"].(string); ok {
				methodName = name
				log.Printf("[INFO] Tool name: %s", name)
			}
		}
	}

	// Only a few specific methods don't need auth
	noAuthMethods := map[string]bool{
		"initialize":              true,
		"notifications/initialized": true,
		"tools/list":              true,
	}

	needsAuth = !noAuthMethods[methodName]
	log.Printf("[DEBUG] Method %s requires auth: %v", methodName, needsAuth)

	// For operations requiring auth, ensure we have a user token
	if needsAuth && userToken == "" {
		// Check for Bearer token in Authorization header
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if strings.HasPrefix(token, "gho_") {
				userToken = token
				log.Printf("[DEBUG] Found valid GitHub token in Authorization header")
				goto processRequest
			}
		}
		
		// Get the actual tool/method name that needs auth
		methodName := request.Method
		if request.Method == "tools/call" {
			if params, ok := request.Params.(map[string]interface{}); ok {
				if name, ok := params["name"].(string); ok {
					methodName = name
				}
			}
		}
		
		log.Printf("[INFO] Initiating auth flow for %s", methodName)

		// VS Code expects a 401 with WWW-Authenticate header to trigger auth
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="GitHub",authorization_uri="%s/oauth/authorize"`, p.serverURL))
		w.WriteHeader(http.StatusUnauthorized)
		
		// VS Code specific error format
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      request.ID,
			"error": map[string]interface{}{
				"code":    -32001,
				"message": "Authorization required",
				"data": map[string]interface{}{
					"method": methodName,
					"providerId": "github",
					"scopes": []string{"user", "repo", "read:org"},
				},
			},
		})
		return
	}

processRequest:
	// Select the appropriate token:
	// - Use bot token for non-auth operations (listing tools, etc)
	// - Use user token for authenticated operations (accessing GHES)
	token := botToken
	if needsAuth {
		token = userToken
		log.Printf("[DEBUG] Using user token for authenticated operation: %s", request.Method)
	}

	// Restart the server if using a different token
	if p.cmd != nil && token != p.botToken {
		log.Printf("[DEBUG] Restarting MCP server with new token")
		if err := p.startMCPServer(token); err != nil {
			log.Printf("[ERROR] Failed to restart MCP server with new token: %v", err)
			http.Error(w, "Failed to proxy request", http.StatusInternalServerError)
			return
		}
		p.botToken = token // Update the token so we don't restart unnecessarily
	}

	// Lock for STDIO operations
	mu.Lock()
	defer mu.Unlock()

	// Try to write request, restart process if pipe is broken
	log.Printf("[DEBUG] Writing request to STDIN: %s", string(body))
	_, err = p.stdin.Write(append(body, '\n'))
	if err != nil {
		log.Printf("[WARN] Failed to write to STDIN: %v, attempting to restart MCP server", err)
		if err := p.startMCPServer(token); err != nil {
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
		respBytes, err := reader.ReadBytes('\n')
		if err != nil {
			errChan <- err
			return
		}
		respChan <- respBytes
	}()

	var respBytes []byte

	// Wait for response with timeout
	select {
	case rb := <-respChan:
		respBytes = rb
	case err := <-errChan:
		log.Printf("[ERROR] Failed to read from STDOUT: %v", err)
		http.Error(w, "Failed to read proxy response", http.StatusInternalServerError)
		return
	case <-time.After(10 * time.Second):
		log.Printf("[ERROR] Timeout reading response from MCP server")
		http.Error(w, "Timeout reading proxy response", http.StatusGatewayTimeout)
		return
	}

	// Verify the response is valid JSON and trim any whitespace/newlines
	trimmedResp := bytes.TrimSpace(respBytes)
	var jsonResp map[string]interface{}
	if err := json.Unmarshal(trimmedResp, &jsonResp); err != nil {
		log.Printf("[ERROR] Invalid JSON response from MCP server: %s - %v", trimmedResp, err)
		http.Error(w, "Invalid response from proxy", http.StatusInternalServerError)
		return
	}

	log.Printf("[DEBUG] Response from STDOUT: %s", string(trimmedResp))

	// Set response headers
	w.Header().Set("Content-Type", "application/json")

	// Write the response
	w.Write(trimmedResp)
}