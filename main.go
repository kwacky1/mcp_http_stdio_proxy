package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    "github.com/kwacky1/mcp_http_stdio_proxy/internal/auth"
    "github.com/kwacky1/mcp_http_stdio_proxy/internal/proxy"
    "github.com/kwacky1/mcp_http_stdio_proxy/internal/session"
)

func getEnvOrDefault(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func validateConfig(config auth.Config) error {
    if config.AppID == "" {
        return fmt.Errorf("GITHUB_APP_ID is required")
    }
    if config.AppSlug == "" {
        return fmt.Errorf("GITHUB_APP_SLUG is required")
    }
    if config.ClientID == "" {
        return fmt.Errorf("GITHUB_CLIENT_ID is required")
    }
    if !strings.HasPrefix(config.ClientID, "Iv1.") {
        return fmt.Errorf("GITHUB_CLIENT_ID must start with 'Iv1.'")
    }
    if config.PrivateKey == "" && config.PrivateKeyPath == "" {
        return fmt.Errorf("either GITHUB_PRIVATE_KEY or GITHUB_PRIVATE_KEY_PATH is required")
    }
    log.Printf("[INFO] Using GitHub client ID: %s", config.ClientID)
    return nil
}

var (
    config = auth.Config{
        AppID:          os.Getenv("GITHUB_APP_ID"),
        AppSlug:        os.Getenv("GITHUB_APP_SLUG"),
        ClientID:       os.Getenv("GITHUB_CLIENT_ID"),  // Get from environment
        ClientSecret:   os.Getenv("GITHUB_CLIENT_SECRET"),  // Get client secret from environment
        PrivateKey:     os.Getenv("GITHUB_PRIVATE_KEY"),
        PrivateKeyPath: os.Getenv("GITHUB_PRIVATE_KEY_PATH"),
        GithubHost:     getEnvOrDefault("GITHUB_HOST", "https://git.ethernest.com"),
        ServerURL:      getEnvOrDefault("MCP_HOST", "http://localhost:8080"),
    }
    botToken      = os.Getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
    webhookSecret = os.Getenv("GITHUB_WEBHOOK_SECRET")
)

func main() {
    // Validate configuration
    if err := validateConfig(config); err != nil {
        log.Fatalf("Configuration error: %v", err)
    }

    // Setup context with cancellation for graceful shutdown
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Setup signal handling for graceful shutdown
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
    go func() {
        sig := <-sigChan
        log.Printf("Received shutdown signal: %v", sig)
        cancel()
    }()

    // Initialize auth handler
    authHandler := auth.NewHandler(config)

    // Start the session cleanup routine
    session.StartCleanupRoutine(ctx)

    // Create a shared proxy instance with bot token
    botToken := os.Getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
    if botToken == "" {
        log.Fatal("GITHUB_PERSONAL_ACCESS_TOKEN is required for MCP server initialization")
    }
    defaultProxy := proxy.New(botToken, config.ServerURL)
    defer defaultProxy.Cleanup()

    // Create a new ServeMux to have more control over routing
    mux := http.NewServeMux()

    // Register auth endpoints first to ensure they take precedence
    // VS Code discovery endpoint
    mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
        log.Printf("[DEBUG] Serving discovery endpoint")
        clientID := authHandler.GetClientID()
        log.Printf("[DEBUG] Using client ID: %s", clientID)

        serverURL := authHandler.GetServerURL()
		config := map[string]interface{}{
			"issuer":                            serverURL,
			"authorization_endpoint":            fmt.Sprintf("%s/oauth/authorize", serverURL),
			"token_endpoint":                   fmt.Sprintf("%s/oauth/token", serverURL),
			"userinfo_endpoint":               fmt.Sprintf("%s/oauth/userinfo", serverURL),
			"scopes_supported":                 []string{"user", "repo", "read:org"},
			"response_types_supported":         []string{"code"},
			"token_endpoint_auth_methods_supported": []string{"none"},
			"code_challenge_methods_supported": []string{"S256"},
			"grant_types_supported":           []string{"authorization_code"},
			"client_id":                       clientID,
		}
		
		log.Printf("[DEBUG] Discovery request from User-Agent: %s", r.Header.Get("User-Agent"))
		log.Printf("[DEBUG] Discovery request headers: %+v", r.Header)
		
		w.Header().Set("Content-Type", "application/json")
        if err := json.NewEncoder(w).Encode(config); err != nil {
            log.Printf("[ERROR] Failed to encode discovery response: %v", err)
        } else {
            log.Printf("[DEBUG] Successfully served discovery endpoint")
        }
    })    // OAuth endpoints
    mux.HandleFunc("/oauth/authorize", authHandler.Authorize)
    mux.HandleFunc("/oauth/callback", authHandler.Callback)
    mux.HandleFunc("/oauth/token", authHandler.Token)
    mux.HandleFunc("/oauth/register", authHandler.Register)  // Add registration endpoint

    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        // Only allow specific paths
        allowedPaths := []string{
            "/",               // Root path for MCP requests
            "/.well-known/",  // OAuth discovery endpoint
            "/oauth/",        // OAuth endpoints including registration
        }

        pathAllowed := false
        for _, path := range allowedPaths {
            if strings.HasPrefix(r.URL.Path, path) {
                pathAllowed = true
                break
            }
        }

        if !pathAllowed {
            log.Printf("Rejected request to unauthorized path: %s %s", r.Method, r.URL.Path)
            http.NotFound(w, r)
            return
        }

        log.Printf("Incoming request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
        
        // No need to explicitly ignore OAuth-related GET requests as they are handled by the mux
        
        // For POST requests, ensure it's JSON content
        if r.Method == "POST" {
            contentType := r.Header.Get("Content-Type")
            if !strings.Contains(contentType, "application/json") {
                log.Printf("Rejected non-JSON POST request with Content-Type: %s", contentType)
                http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
                return
            }
        }

        // Handle basic health check GET requests without query parameters
        if r.Method == "GET" && r.URL.RawQuery == "" {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]interface{}{
                "jsonrpc": "2.0",
                "result": map[string]interface{}{
                    "status": "ok",
                },
            })
            return
        }

        // Check for authentication header
        var token string
        if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
            token = strings.TrimPrefix(authHeader, "Bearer ")
        }

        // Check for session cookie if no auth header
        if token == "" {
            if cookie, err := r.Cookie(session.SessionCookie); err == nil {
                if sess := session.Get(cookie.Value); sess != nil {
                    token = sess.AccessToken
                }
            }
        }

        // Use the shared proxy instance
        defaultProxy.ProxyMCP(w, r, token, botToken)
    })

    // Create server with timeout configuration
    server := &http.Server{
        Addr:         ":8080",
        Handler:      mux,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    // Run server in a goroutine so we can handle shutdown
    go func() {
        log.Printf("Starting server on :8080")
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Printf("Server error: %v", err)
        }
    }()

    // Wait for context cancellation (from signal handler)
    <-ctx.Done()
    log.Println("Shutting down server...")

    // Create shutdown context with timeout
    shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer shutdownCancel()

    // Attempt graceful shutdown
    if err := server.Shutdown(shutdownCtx); err != nil {
        log.Printf("Server shutdown error: %v", err)
    }

    // Ensure all cleanup is done
    if defaultProxy != nil {
        defaultProxy.Cleanup()
    }
    session.CleanupAll()
}