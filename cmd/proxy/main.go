package main

import (
	"antigravity-proxy-go/internal/auth"
	"antigravity-proxy-go/internal/config"
	"antigravity-proxy-go/internal/database"
	"antigravity-proxy-go/internal/mappers"
	"antigravity-proxy-go/internal/mcp"
	"antigravity-proxy-go/internal/upstream"
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dchest/captcha"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

var (
	modelCache   []string
	modelCacheMu sync.RWMutex
	captchaStore = make(map[string]string)
	captchaMu    sync.RWMutex
)

func updateModelCache(tm *auth.TokenManager, up *upstream.Client) {
	acc, err := tm.GetToken()
	if err != nil {
		log.Printf("Failed to get token for model cache update: %v", err)
		return
	}

	if acc.ProjectID == "" {
		pid, _, err := up.FetchProjectDetails(acc.Token.AccessToken)
		if err != nil {
			log.Printf("Failed to fetch project details for cache update: %v", err)
			return
		}
		acc.ProjectID = pid
	}

	modelsMap, err := up.FetchQuota(acc.Token.AccessToken, acc.ProjectID)
	if err != nil {
		log.Printf("Failed to fetch models for cache: %v", err)
		return
	}

	var newCache []string
	for name := range modelsMap {
		newCache = append(newCache, name)
	}

	modelCacheMu.Lock()
	modelCache = newCache
	modelCacheMu.Unlock()
	log.Printf("Updated model cache with %d models", len(newCache))
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, x-api-key, anthropic-version")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		mode := cfg.Proxy.AuthMode
		if mode == "auto" {
			// Auto mode: If host exposes to 0.0.0.0 (LAN/Public), mandate auth.
			// If host is strict local (127.0.0.1 or localhost), default to off.
			if cfg.Server.Host == "0.0.0.0" {
				mode = "all_except_health"
			} else {
				mode = "off"
			}
		}

		if mode == "off" {
			c.Next()
			return
		}

		// If no keys are configured, skip auth unless it's explicitly strict
		// Modified: Now we also support DB keys and Sessions, so we shouldn't skip just because Config keys are empty,
		// unless we are sure we want "no auth" when config is empty.
		// But "strict" or "all_except_health" implies we WANT auth.
		// If both strict/all_except_health are set, we MUST check auth.

		if mode == "all_except_health" && c.Request.URL.Path == "/healthz" {
			c.Next()
			return
		}

		apiKey := c.GetHeader("Authorization")
		if apiKey == "" {
			apiKey = c.GetHeader("x-api-key")
		} else if strings.HasPrefix(apiKey, "Bearer ") {
			apiKey = strings.TrimPrefix(apiKey, "Bearer ")
		}

		authorized := false

		// 1. Check Config Keys
		if len(cfg.Proxy.APIKeys) > 0 {
			for _, k := range cfg.Proxy.APIKeys {
				if apiKey == k && apiKey != "" {
					authorized = true
					c.Set("auth_method", "config_key")
					break
				}
			}
		}

		// 2. Check Database Keys (if key provided and not already authorized)
		if !authorized && apiKey != "" {
			valid, err := database.ValidateAPIKey(apiKey)
			if err == nil && valid {
				authorized = true
				c.Set("auth_method", "db_key")
			}
		}

		// 3. Check Session Cookies (WebUI or Admin)
		if !authorized {
			// A. Check for WebUI Session (antimatter_session)
			sessionID, err := c.Cookie("antimatter_session")
			if err == nil && sessionID != "" {
				c.Set("userID", "session_"+sessionID)
				c.Set("auth_method", "session")
				authorized = true
			}

			// B. Check for Admin Session (admin_session) - Allows Admin Panel to access API
			if !authorized {
				sessionToken, err := c.Cookie("admin_session")
				if err == nil && sessionToken != "" {
					token, err := jwt.Parse(sessionToken, func(token *jwt.Token) (interface{}, error) {
						if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
							return nil, fmt.Errorf("unexpected signing method")
						}
						key := cfg.Admin.JWTSecret
						if key == "" {
							key = "default-secret-change-me"
						}
						return []byte(key), nil
					})

					if err == nil && token.Valid {
						// Also check revocation if needed, but for now this proves admin auth
						c.Set("userID", "admin_session")
						c.Set("auth_method", "admin_session")
						authorized = true
					}
				}
			}

			// C. Legacy JWT (antimatter_token)
			if !authorized {
				tokenString, err := c.Cookie("antimatter_token")
				if err == nil && tokenString != "" {
					token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
						return []byte(cfg.Admin.JWTSecret), nil
					})
					if err == nil && token.Valid {
						if claims, ok := token.Claims.(jwt.MapClaims); ok {
							c.Set("userID", claims["email"])
							c.Set("auth_method", "jwt_token")
							authorized = true
						}
					}
				}
			}
		}

		// Compatibility: If not strict, and no auth provided/valid, and NO config keys were set...
		// The original logic allowed access if config APIKeys was empty and mode != strict.
		// We preserve this behavior ONLY if no auth headers/cookies were presented at all?
		// No, user wants to allow Google/DB keys.
		// If mode is set to "strict" or "all_except_health", we EXPECT auth.

		if !authorized {
			// If we are here, no valid auth method found.

			// Legacy fallback: If NOT strict, and config keys are empty, we used to allow.
			// But now we have other auth methods.
			// If the user INTENDED to have auth enabled (by setting auth_mode), we should block.
			// If auth_mode is "off", we returned early at top.

			// Redirect to login if Accept header allows HTML (Browser)
			if strings.Contains(c.Request.Header.Get("Accept"), "text/html") {
				// Don't redirect loop if already on login page - assume /login is handled elsewhere or frontend
				// For now just return 401/JSON or a redirect suggestion
				// c.Redirect(http.StatusFound, "/login") // We don't have a user login page yet
			}

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":     "Unauthorized",
				"message":   "Authentication required via API Key or Login",
				"login_url": "/login", // Hint for frontend
			})
			return
		}

		// CSRF Check for WebUI Session
		// If authenticated via Session Cookie, enforce CSRF for state-changing requests (like Chat)
		if authorized {
			authMethod, _ := c.Get("auth_method")
			if authMethod == "session" {
				// For WebUI sessions, we require CSRF token for POST/PUT/DELETE
				if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "DELETE" {
					csrfCookie, _ := c.Cookie("csrf_token")
					csrfHeader := c.GetHeader("X-CSRF-Token")

					// Special case: If no CSRF cookie exists yet for a new session, we might be lenient OR
					// the frontend should have fetched it.
					// Actually, allow if both are missing? No, that defeats the point.
					// But we need to ensure the frontend GETs a CSRF token first.
					// We'll set a CSRF cookie on the index page load (handled in indexHandler).

					if csrfCookie == "" || csrfHeader == "" || csrfCookie != csrfHeader {
						c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "CSRF token mismatch"})
						return
					}
				}
			}
		}

		c.Set("userID", apiKey)
		c.Next()
	}
}

func AdminMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !cfg.Admin.Enabled {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// 1. Check for Direct Admin Password or JWT in Header (Scripts/API) - Bypasses CSRF
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			tokenVal := strings.TrimPrefix(authHeader, "Bearer ")
			// Allow using the Admin Password directly as a Bearer token
			if tokenVal == cfg.Admin.Password {
				c.Set("admin_user", "admin_direct")
				c.Next()
				return
			}

			// Allow using a valid session JWT as a Bearer token
			token, err := jwt.Parse(tokenVal, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				key := cfg.Admin.JWTSecret
				if key == "" {
					key = "default-secret-change-me"
				}
				return []byte(key), nil
			})
			if err == nil && token.Valid {
				if !database.IsTokenRevoked(token.Raw) {
					c.Set("admin_user", "admin_jwt_header")
					c.Next()
					return
				}
			}
		}

		// 2. Browser Session Auth (Cookie) - Requires CSRF
		sessionToken, err := c.Cookie("admin_session")
		if err != nil || sessionToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		token, err := jwt.Parse(sessionToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			key := cfg.Admin.JWTSecret
			if key == "" {
				key = "default-secret-change-me" // Fallback
			}
			return []byte(key), nil
		})

		if err != nil || !token.Valid {
			c.SetCookie("admin_session", "", -1, "/", "", false, true)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
			return
		}

		// Blacklist Check
		if database.IsTokenRevoked(token.Raw) {
			c.SetCookie("admin_session", "", -1, "/", "", false, true)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Session revoked"})
			return
		}

		// CSRF Check for mutating requests (Only for Cookie Auth)
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "DELETE" {
			csrfCookie, _ := c.Cookie("csrf_token")
			csrfHeader := c.GetHeader("X-CSRF-Token")
			if csrfCookie == "" || csrfHeader == "" || csrfCookie != csrfHeader {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "CSRF token mismatch"})
				return
			}
		}

		c.Next()
	}
}

func chatCompletionsHandler(tm *auth.TokenManager, up *upstream.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var trace strings.Builder
		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("=== INCOMING REQUEST (%s) ===\n", time.Now().Format(time.RFC3339)))
			trace.WriteString(fmt.Sprintf("Path: %s\n", c.Request.URL.Path))
		}
		defer func() {
			if cfg.Proxy.Debug && trace.Len() > 0 {
				writeTraceLog(&trace, "trace_chat")
			}
		}()

		body, _ := io.ReadAll(c.Request.Body)
		if cfg.Proxy.Debug {
			trace.WriteString("\n=== REQUEST BODY ===\n")
			trace.Write(body)
			trace.WriteString("\n")
		}

		var req struct {
			Stream bool   `json:"stream"`
			Model  string `json:"model"`
		}
		json.Unmarshal(body, &req)

		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("Requested Model: %s\n", req.Model))
		}

		geminiReq, requestedModel, err := mappers.TransformOpenAIRequest(body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Inject Global System Prompt if configured
		if cfg.Models.SystemPrompt != "" {
			newPart := map[string]interface{}{
				"text": cfg.Models.SystemPrompt,
			}

			if sysInst, ok := geminiReq["system_instruction"].(map[string]interface{}); ok {
				if parts, ok := sysInst["parts"].([]map[string]interface{}); ok {
					// Prepend global prompt
					geminiReq["system_instruction"].(map[string]interface{})["parts"] = append([]map[string]interface{}{newPart}, parts...)
				} else {
					// Malformed parts, reset
					sysInst["parts"] = []map[string]interface{}{newPart}
				}
			} else {
				// No existing system instruction, create one
				geminiReq["system_instruction"] = map[string]interface{}{
					"parts": []map[string]interface{}{newPart},
				}
			}
		}

		modelCacheMu.RLock()
		model := resolveModel(requestedModel, cfg)
		modelCacheMu.RUnlock()

		// Enforce WebUI Session Limit
		// Check if this is a WebUI session based on auth method or cookie presence
		authMethod, _ := c.Get("auth_method")
		// "session" is set in AuthMiddleware for cookie-based auth
		if authMethod == "session" {
			sessionID, err := c.Cookie("antimatter_session")
			if err == nil && sessionID != "" {
				// 1. Request Usage Check
				if cfg.Session.WebUIRequestLimit > 0 {
					count, err := database.GetSessionRequestCount(sessionID)
					if err == nil && count >= cfg.Session.WebUIRequestLimit {
						c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
							"error": fmt.Sprintf("Session request limit reached (%d/%d). Please refresh your session or contact admin.", count, cfg.Session.WebUIRequestLimit),
						})
						return
					}
				}

				// 2. Token Usage Check
				if cfg.Session.WebUITokenLimit > 0 {
					tokens, err := database.GetSessionTokenCount(sessionID)
					// Verify tokens against limit
					if err == nil && tokens >= int64(cfg.Session.WebUITokenLimit) {
						c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
							"error": fmt.Sprintf("Token limiti doldu (%d/%d).", tokens, cfg.Session.WebUITokenLimit),
						})
						return
					}
				}
			}
		}

		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("Resolved Model: %s\n", model))
		}

		if req.Stream {
			// Get or create session ID
			sessionID, _ := c.Cookie("antimatter_session")
			if sessionID == "" {
				sessionID = uuid.New().String()
				// Set cookie with 30 days expiration
				c.SetCookie("antimatter_session", sessionID, 3600*24*30, "/", "", false, false)
			}

			userID := c.ClientIP()
			if val, exists := c.Get("userID"); exists && val != "" {
				userID = val.(string)
			}

			// Capture full response for logging
			var fullResponse strings.Builder
			start := time.Now()

			executeStreamWithRetry(c, tm, up, model, geminiReq, cfg, &trace, func(line string) (string, bool) {
				out, ok := mappers.TransformOpenAIStreamChunk(line, model)
				if ok {
					// Extract content for logging (best effort)
					if strings.HasPrefix(out, "data: ") && out != "data: [DONE]" {
						jsonStr := strings.TrimPrefix(out, "data: ")
						var chunk struct {
							Choices []struct {
								Delta struct {
									Content string `json:"content"`
								} `json:"delta"`
							} `json:"choices"`
						}
						// Fast, lax unmarshal
						if json.Unmarshal([]byte(jsonStr), &chunk) == nil && len(chunk.Choices) > 0 {
							fullResponse.WriteString(chunk.Choices[0].Delta.Content)
						}
					}
				}
				return out, ok
			})

			// Log Streaming Request (Async)
			go func() {
				latency := time.Since(start).Milliseconds()
				var prompt string
				// Extract OpenAI Prompt from original body
				var fullReq struct {
					Messages []struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"messages"`
				}
				json.Unmarshal(body, &fullReq)
				if len(fullReq.Messages) > 0 {
					lastMsg := fullReq.Messages[len(fullReq.Messages)-1]
					prompt = fmt.Sprintf("[%s]: %s", lastMsg.Role, lastMsg.Content)
				}

				sessionID, _ := c.Cookie("antimatter_session")
				responseStr := fullResponse.String()

				// Simple Token Estimation (1 token ~= 4 chars)
				pTokens := len(prompt) / 4
				cTokens := len(responseStr) / 4
				if pTokens == 0 && len(prompt) > 0 {
					pTokens = 1
				}
				if cTokens == 0 && len(responseStr) > 0 {
					cTokens = 1
				}

				database.LogRequest(context.Background(), &database.RequestLog{
					Model:            model,
					UserID:           userID,
					SessionID:        sessionID,
					PromptTokens:     pTokens,
					CompletionTokens: cTokens,
					TotalTokens:      pTokens + cTokens,
					Status:           200,
					LatencyMS:        latency,
					Prompt:           prompt,
					Response:         responseStr,
				})
			}()
		} else {
			// Get or create session ID
			sessionID, _ := c.Cookie("antimatter_session")
			if sessionID == "" {
				sessionID = uuid.New().String()
				// Set cookie with 30 days expiration
				c.SetCookie("antimatter_session", sessionID, 3600*24*30, "/", "", false, false)
			}

			start := time.Now()
			executeWithRetry(c, tm, up, model, geminiReq, cfg, &trace, func(resp []byte) interface{} {
				out, usage, _ := mappers.TransformOpenAIResponse(resp, model)

				// Extract prompt
				var prompt string
				// OpenAI Request: req.Messages (which we need to extract from body again or just unmarshal completely at start)
				// Re-unmarshalling full body to get messages
				var fullReq struct {
					Messages []struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"messages"`
				}
				json.Unmarshal(body, &fullReq)
				if len(fullReq.Messages) > 0 {
					lastMsg := fullReq.Messages[len(fullReq.Messages)-1]
					prompt = fmt.Sprintf("[%s]: %s", lastMsg.Role, lastMsg.Content)
				}

				userID := c.ClientIP()
				if val, exists := c.Get("userID"); exists && val != "" {
					userID = val.(string)
				}

				// Extract full response based on simple JSON structure assumption for now
				// (Assuming 'out' is the final JSON response)

				// Extract full response based on simple JSON structure assumption for now
				// (Assuming 'out' is the final JSON response)
				var responseText string
				var thoughtText string

				if choices, ok := out["choices"].([]interface{}); ok && len(choices) > 0 {
					if choice, ok := choices[0].(map[string]interface{}); ok {
						if msg, ok := choice["message"].(map[string]interface{}); ok {
							if content, ok := msg["content"].(string); ok {
								responseText = content
							}
							if thought, ok := msg["thought"].(string); ok {
								thoughtText = thought
							}
						}
					}
				}

				// Log to DB
				go database.LogRequest(context.Background(), &database.RequestLog{
					Model:            model,
					UserID:           userID,
					SessionID:        sessionID,
					Response:         responseText,
					Thought:          thoughtText,
					PromptTokens:     usage.PromptTokens,
					CompletionTokens: usage.CompletionTokens,
					TotalTokens:      usage.TotalTokens,
					Status:           200,
					LatencyMS:        time.Since(start).Milliseconds(),
					Prompt:           prompt,
				})

				return out
			})
		}
	}
}

func resolveModel(requestedModel string, cfg *config.Config) string {
	if requestedModel == "" {
		return cfg.Models.FallbackModel
	}

	// 1. Check cache first
	inCache := false
	for _, m := range modelCache {
		if m == requestedModel {
			inCache = true
			break
		}
	}

	if inCache {
		if cfg.Proxy.Debug {
			log.Printf("Resolved model (cache hit): %s", requestedModel)
		}
		return requestedModel
	}

	// 2. Pass-through logic (Mirroring Rust behavior)
	// If it starts with "gemini-" or contains "thinking", trust the client and pass it through.
	if strings.HasPrefix(requestedModel, "gemini-") || strings.Contains(requestedModel, "thinking") {
		if cfg.Proxy.Debug {
			log.Printf("Resolved model (pass-through): %s", requestedModel)
		}
		return requestedModel
	}

	// 3. Common mappings
	if strings.Contains(requestedModel, "gpt-4") {
		return "gemini-3-pro-high"
	}
	if strings.Contains(requestedModel, "gpt-3.5") || strings.Contains(requestedModel, "mini") {
		return "gemini-3-flash"
	}

	if cfg.Proxy.Debug {
		log.Printf("Resolved model (fallback): %s -> %s", requestedModel, cfg.Models.FallbackModel)
	}
	return cfg.Models.FallbackModel
}

func main() {
	// Load Config
	cfg, err := config.LoadConfig("settings.yaml")
	if err != nil {
		log.Printf("Warning: Failed to load settings.yaml: %v. Using defaults.", err)
		cfg = &config.Config{}
		cfg.Server.Port = 8045
		cfg.Strategy.Type = "round-robin"
		cfg.Proxy.AuthMode = "off"
		cfg.Models.FallbackModel = "gemini-3-flash"
	}

	// Handle random JWT secret
	if cfg.Admin.JWTSecret == "random" {
		bytes := make([]byte, 32)
		if _, err := crand.Read(bytes); err == nil {
			cfg.Admin.JWTSecret = hex.EncodeToString(bytes)
			log.Printf("Admin: Using randomly generated JWT secret")
		} else {
			cfg.Admin.JWTSecret = "fallback-secret-if-rand-fails"
			log.Printf("Warning: Failed to generate random JWT secret, using fallback")
		}
	}

	// Initialize Database
	if err := database.InitDB("usage.db"); err != nil {
		log.Printf("Failed to initialize database: %v", err)
	}

	// Check for login command
	if len(os.Args) > 1 {
		if os.Args[1] == "login" {
			if _, err := auth.Login(); err != nil {
				log.Fatalf("Login failed: %v", err)
			}
			return
		}
		if os.Args[1] == "status" {
			runStatus()
			return
		}
		if os.Args[1] == "mcp" {
			// Ensure DB is init
			if err := database.InitDB("usage.db"); err != nil {
				log.Fatalf("Failed to initialize database: %v", err)
			}
			srv := mcp.CreateMCPServer()
			log.Println("Starting MCP Server (Stdio)...")
			if err := mcpserver.ServeStdio(srv); err != nil {
				log.Fatalf("MCP Server Error: %v", err)
			}
			return
		}
	}

	// Check for flags
	enableWebUI := false
	enableProxyAdmin := false
	for _, arg := range os.Args {
		if arg == "webui" {
			enableWebUI = true
		}
		if arg == "proxyadmin" {
			enableProxyAdmin = true
			enableWebUI = true
			// Force auth to be enabled in proxyadmin mode
			cfg.Proxy.AuthMode = "all_except_health"
			log.Println("ProxyAdmin mode: Enforcing secure authentication (all_except_health)")
		}
	}

	// Log MCP info if enabled
	if cfg.MCP.Mode == "server" {
		log.Println("FYI: MCP Server Mode is configured. To use it, configure your AI Client to run 'antimatter.exe mcp'.")
	}

	tm := auth.NewTokenManager(cfg.Strategy.Type)
	up := upstream.NewClient()

	// Load accounts from config (settings.yaml)
	for _, acc := range cfg.Accounts {
		tm.AddAccount(acc.Email, acc.RefreshToken, acc.Disabled, acc.DisabledAt, acc.DisabledReason)
		if acc.Disabled {
			log.Printf("Added account: %s (DISABLED: %s)", acc.Email, acc.DisabledReason)
		} else {
			log.Printf("Added account: %s", acc.Email)
		}
	}

	// Initial model cache update
	go func() {
		updateModelCache(tm, up)
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			updateModelCache(tm, up)
		}
	}()

	r := gin.Default()
	r.Use(CORSMiddleware())
	r.Use(AuthMiddleware(cfg))

	// Serve Frontend
	// Serve Frontend
	// Serve Frontend on Main Port (8045) as well
	r.Static("/static", "./web/static")
	// Custom handler for index to set session cookie
	indexHandler := func(c *gin.Context) {
		if enableProxyAdmin {
			c.Redirect(http.StatusFound, "/admin.html")
			return
		}
		// Always generate a new session ID on refresh/load
		newSessionID := uuid.New().String()
		// Set cookie: name, value, maxAge (0=session), path, domain, secure, httpOnly
		c.SetCookie("antimatter_session", newSessionID, 0, "/", "", false, true)

		// Set CSRF Token cookie (readable by JS)
		csrfToken := uuid.New().String()
		c.SetCookie("csrf_token", csrfToken, 0, "/", "", false, false) // HttpOnly=false

		c.File("./web/index.html")
	}
	r.GET("/index.html", indexHandler)
	r.StaticFile("/admin.html", "./web/admin.html")
	r.GET("/", indexHandler)

	// anthropicHandler definition moved to top to support WebUI usage
	anthropicHandler := func(c *gin.Context) {
		var trace strings.Builder
		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("=== INCOMING ANTHROPIC REQUEST (%s) ===\n", time.Now().Format(time.RFC3339)))
			trace.WriteString(fmt.Sprintf("Path: %s\n", c.Request.URL.Path))
		}
		defer func() {
			if cfg.Proxy.Debug && trace.Len() > 0 {
				writeTraceLog(&trace, "trace_anthropic")
			}
		}()

		body, _ := io.ReadAll(c.Request.Body)
		if cfg.Proxy.Debug {
			trace.WriteString("\n=== REQUEST BODY ===\n")
			trace.Write(body)
			trace.WriteString("\n")
		}

		var req struct {
			Stream bool   `json:"stream"`
			Model  string `json:"model"`
		}
		json.Unmarshal(body, &req)

		geminiReq, requestedModel, err := mappers.TransformAnthropicRequest(body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		modelCacheMu.RLock()
		model := resolveModel(requestedModel, cfg)
		modelCacheMu.RUnlock()

		if req.Stream {
			executeStreamWithRetry(c, tm, up, model, geminiReq, cfg, &trace, func(line string) (string, bool) {
				// TODO: Implement proper Anthropic SSE transformer if needed.
				// For now, let's use a simpler passthrough or similar logic.
				// For brevity, we reuse OpenAI chunk logic but it might need adjustments for Anthropic clients.
				return mappers.TransformOpenAIStreamChunk(line, model)
			})
		} else {
			executeWithRetry(c, tm, up, model, geminiReq, cfg, &trace, func(resp []byte) interface{} {
				out, _ := mappers.TransformAnthropicResponse(resp, model)
				return out
			})
		}

	}

	modelsHandler := func(c *gin.Context) {
		// Ensure we have at least one usable account before returning models
		// This prevents the UI from thinking we are "logged in" just because it got a default list.
		if _, err := tm.GetToken(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "No accounts available",
			})
			return
		}

		defaultModels := []string{
			"gemini-2.5-pro",
			"gemini-2.5-flash",
			"gpt-oss-120b-medium",
			"claude-sonnet-4-5-thinking",
			"gemini-3-pro-low",
			"chat_23310",
			"rev19-uic3-1p",
			"claude-opus-4-5-thinking",
			"gemini-2.5-flash-lite",
			"gemini-3-pro-image",
			"gemini-2.5-flash-thinking",
			"gemini-3-flash",
			"claude-sonnet-4-5",
			"gemini-3-pro-high",
			"chat_20706",
		}

		modelCacheMu.RLock()
		cached := make(map[string]bool)
		for _, m := range modelCache {
			cached[m] = true
		}
		modelCacheMu.RUnlock()

		log.Printf("[DEBUG] modelsHandler called. Default models count: %d", len(defaultModels))

		// Merge default models
		for _, m := range defaultModels {
			cached[m] = true
		}

		var finalModels []string
		for m := range cached {
			// Filter out internal/debug models starting with "chat_"
			if !strings.HasPrefix(m, "chat_") {
				finalModels = append(finalModels, m)
			}
		}
		log.Printf("[DEBUG] Final models count: %d", len(finalModels))

		models := []map[string]interface{}{}
		for _, m := range finalModels {
			models = append(models, map[string]interface{}{
				"id":       m,
				"object":   "model",
				"created":  1700000000,
				"owned_by": "google",
			})
		}
		c.JSON(http.StatusOK, gin.H{
			"object": "list",
			"data":   models,
		})
	}

	// Optional Separate WebUI Port (8046) - kept for backward compat if needed, but redundant now
	if enableWebUI {
		go func() {
			uiRouter := gin.Default()
			// Serve static files
			uiRouter.Static("/static", "./web/static")

			if enableProxyAdmin {
				uiRouter.GET("/", func(c *gin.Context) {
					c.Redirect(http.StatusFound, "/admin.html")
				})
				uiRouter.GET("/index.html", func(c *gin.Context) {
					c.Redirect(http.StatusFound, "/admin.html")
				})
			} else {
				uiRouter.StaticFile("/index.html", "./web/index.html")
				uiRouter.GET("/", func(c *gin.Context) {
					// Always generate a new session ID on refresh/load
					newSessionID := uuid.New().String()
					// Set cookie: name, value, maxAge (0=session), path, domain, secure, httpOnly
					c.SetCookie("antimatter_session", newSessionID, 0, "/", "", false, true)
					c.File("./web/index.html")
				})
			}

			uiRouter.StaticFile("/admin.html", "./web/admin.html")

			// Add models handler for WebUI (fix for 404 on port 8046)
			uiRouter.GET("/v1/models", modelsHandler)
			uiRouter.GET("/models", modelsHandler)

			// Mirror main API endpoints on WebUI port for convenience/testing (Protected by AuthMiddleware)
			// This allows using port 8046 for API calls just like 8045
			apiMirror := uiRouter.Group("/")
			apiMirror.Use(AuthMiddleware(cfg))
			{
				apiMirror.POST("/v1/chat/completions", chatCompletionsHandler(tm, up, cfg))
				apiMirror.POST("/chat/completions", chatCompletionsHandler(tm, up, cfg))
				apiMirror.POST("/v1/messages", anthropicHandler)
				apiMirror.POST("/messages", anthropicHandler)
			}

			// Login Endpoint for WebUI
			uiRouter.POST("/api/antigravity_login", func(c *gin.Context) {
				// Start the login flow (listener + URL generation)
				url, waitFunc, err := auth.StartLoginServer()
				if err != nil {
					log.Printf("WebUI Login failed to start: %v", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}

				// Run the waiter in a goroutine
				go func() {
					acc, err := waitFunc()
					if err != nil {
						log.Printf("WebUI Login wait error: %v", err)
						return
					}
					// Add the new account to the TokenManager
					if acc != nil {
						tm.AddAccount(acc.Email, acc.RefreshToken, false, 0, "")
						log.Printf("Account %s added to TokenManager via WebUI", acc.Email)
					}
				}()

				// Return the URL to the client immediately
				c.JSON(http.StatusOK, gin.H{
					"status": "pending",
					"url":    url,
				})
			})

			// --- ADMIN API FOR WEBUI (Port 8046) ---
			uiAdmin := uiRouter.Group("/api/admin")

			uiAdmin.GET("/captcha", func(c *gin.Context) {
				// Generate new captcha with dchest/captcha
				captchaID := captcha.NewLen(6) // 6 digits
				c.JSON(http.StatusOK, gin.H{
					"id": captchaID,
				})
			})

			// Serve captcha image
			uiAdmin.GET("/captcha/image/:id", func(c *gin.Context) {
				captchaID := c.Param("id")
				c.Header("Content-Type", "image/png")
				c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
				captcha.WriteImage(c.Writer, captchaID, captcha.StdWidth, captcha.StdHeight)
			})

			uiAdmin.POST("/login", func(c *gin.Context) {
				ip := c.ClientIP()
				banned, reason, err := database.IsBanned(ip)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal error"})
					return
				}
				if banned {
					c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("IP Banned: %s", reason)})
					return
				}

				failCount, _ := database.GetFailureCount(ip)
				var req struct {
					Password      string `json:"password"`
					CaptchaId     string `json:"captcha_id"`
					CaptchaAnswer string `json:"captcha_answer"`
				}
				if err := c.BindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
					return
				}

				if failCount >= 5 {
					if req.CaptchaId == "" || req.CaptchaAnswer == "" {
						c.JSON(http.StatusTooManyRequests, gin.H{"error": "Captcha required", "captcha_required": true})
						return
					}
					// Verify captcha using dchest/captcha
					if !captcha.VerifyString(req.CaptchaId, req.CaptchaAnswer) {
						database.IncrementFailure(ip)
						c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Captcha", "captcha_required": true})
						return
					}
				}

				if req.Password == cfg.Admin.Password && cfg.Admin.Enabled {
					database.ResetFailure(ip)

					// Generate JWT
					token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
						"role": "admin",
						"exp":  time.Now().Add(24 * time.Hour).Unix(),
						"iat":  time.Now().Unix(),
					})

					key := cfg.Admin.JWTSecret
					if key == "" {
						key = "default-secret-change-me"
					}

					tokenString, err := token.SignedString([]byte(key))
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
						return
					}

					// Generate CSRF Token
					csrfToken := uuid.New().String()
					c.SetCookie("csrf_token", csrfToken, 3600*24, "/", "", false, false) // HttpOnly=false for JS access

					c.SetCookie("admin_session", tokenString, 3600*24, "/", "", false, true)
					c.JSON(http.StatusOK, gin.H{"status": "ok"})
				} else {
					newCount, _ := database.IncrementFailure(ip)
					if newCount >= 10 {
						database.BanIP(ip, "Too many failed login attempts")
						c.JSON(http.StatusForbidden, gin.H{"error": "Too many attempts. IP Banned."})
					} else if newCount >= 5 {
						c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password", "captcha_required": true})
					} else {
						c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
					}
				}
			})

			uiAdmin.Use(AdminMiddleware(cfg))
			uiAdmin.POST("/logout", func(c *gin.Context) {
				sessionToken, _ := c.Cookie("admin_session")
				if sessionToken != "" {
					// Parse unverified to get expiration
					token, _, _ := new(jwt.Parser).ParseUnverified(sessionToken, jwt.MapClaims{})
					if token != nil {
						if claims, ok := token.Claims.(jwt.MapClaims); ok {
							if exp, ok := claims["exp"].(float64); ok {
								database.RevokeToken(sessionToken, time.Unix(int64(exp), 0))
							}
						}
					}
				}
				c.SetCookie("admin_session", "", -1, "/", "", false, true)
				c.SetCookie("csrf_token", "", -1, "/", "", false, false)
				c.JSON(http.StatusOK, gin.H{"status": "logged out"})
			})

			uiAdmin.GET("/stats", func(c *gin.Context) {
				stats, err := database.GetUsageStats()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, stats)
			})

			uiAdmin.GET("/logs", func(c *gin.Context) {
				limitStr := c.DefaultQuery("limit", "10")
				limit, _ := strconv.Atoi(limitStr)
				if limit < 1 {
					limit = 10
				}
				if limit > 100 {
					limit = 100
				}

				logs, err := database.GetRecentLogs(limit)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"data": logs})
			})

			uiAdmin.GET("/sessions", func(c *gin.Context) {
				page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
				limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
				model := c.Query("model")
				ip := c.Query("ip")

				if page < 1 {
					page = 1
				}
				if limit < 1 {
					limit = 10
				}
				if limit > 50 {
					limit = 50
				}

				sessions, total, err := database.GetSessions(page, limit, model, ip)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{
					"data": sessions,
					"pagination": gin.H{
						"page":        page,
						"limit":       limit,
						"total":       total,
						"total_pages": (total + limit - 1) / limit,
					},
				})
			})
			uiAdmin.GET("/session/:sid", func(c *gin.Context) {
				sid := c.Param("sid")
				logs, err := database.GetSessionDetails(sid)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"logs": logs})
			})

			// Server Config Handlers
			uiAdmin.GET("/config", func(c *gin.Context) {
				// Return safe config subset
				c.JSON(http.StatusOK, gin.H{
					"server":   cfg.Server,
					"proxy":    cfg.Proxy,
					"models":   cfg.Models,
					"mcp":      cfg.MCP,
					"admin":    gin.H{"enabled": cfg.Admin.Enabled}, // Security: Don't echo password/secret
					"strategy": cfg.Strategy,
					"session":  cfg.Session,
				})
			})

			uiAdmin.POST("/config", func(c *gin.Context) {
				var req map[string]interface{}
				if err := c.BindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
					return
				}

				updates := make(map[string]interface{})

				// Flatten the updates to "key.path" format for UpdateSettings
				if srv, ok := req["server"].(map[string]interface{}); ok {
					if port, ok := srv["port"]; ok {
						updates["server.port"] = port
					}
					if webuiPort, ok := srv["webui_port"]; ok {
						updates["server.webui_port"] = webuiPort
					}
					if host, ok := srv["host"]; ok {
						updates["server.host"] = host
					}
				}
				if prx, ok := req["proxy"].(map[string]interface{}); ok {
					if auth, ok := prx["auth_mode"]; ok {
						updates["proxy.auth_mode"] = auth
					}
					// Deprecated: allow_lan_access removed, ignore
					if debug, ok := prx["debug"]; ok {
						updates["proxy.debug"] = debug
					}
				}
				if mdl, ok := req["models"].(map[string]interface{}); ok {
					if fb, ok := mdl["fallback_model"]; ok {
						updates["models.fallback_model"] = fb
					}
					if sp, ok := mdl["system_prompt"]; ok {
						updates["models.system_prompt"] = sp
					}
				}
				if mcpMap, ok := req["mcp"].(map[string]interface{}); ok {
					if mode, ok := mcpMap["mode"]; ok {
						updates["mcp.mode"] = mode
					}
				}
				if stg, ok := req["strategy"].(map[string]interface{}); ok {
					if t, ok := stg["type"]; ok {
						updates["strategy.type"] = t
					}
				}
				if sess, ok := req["session"].(map[string]interface{}); ok {
					if wrl, ok := sess["webui_request_limit"]; ok {
						updates["session.webui_request_limit"] = wrl
					}
					if wtl, ok := sess["webui_token_limit"]; ok {
						updates["session.webui_token_limit"] = wtl
					}
				}
				if adm, ok := req["admin"].(map[string]interface{}); ok {
					if en, ok := adm["enabled"]; ok {
						updates["admin.enabled"] = en
					}
					if pwd, ok := adm["password"]; ok && pwd != "" {
						updates["admin.password"] = pwd
					}
					// Not allowing JWT secret update via UI for now as it breaks session immediately
				}

				if err := config.UpdateSettings("settings.yaml", updates); err != nil {
					log.Printf("Failed to save settings: %v", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save settings"})
					return
				}

				// Reload config to apply changes immediately where possible
				// Note: Port changes require restart
				newCfg, err := config.LoadConfig("settings.yaml")
				if err == nil {
					// Update global config pointer safely
					cfg.Server = newCfg.Server
					cfg.Proxy = newCfg.Proxy
					cfg.Models = newCfg.Models
					cfg.Session = newCfg.Session             // Update session settings
					cfg.Admin.Enabled = newCfg.Admin.Enabled // Only update enabled/password
					cfg.Admin.Password = newCfg.Admin.Password
					// Keep existing JWT secret if it was random in memory (or reload if it's persistent)
					if cfg.Admin.JWTSecret != "random" && newCfg.Admin.JWTSecret != "random" {
						cfg.Admin.JWTSecret = newCfg.Admin.JWTSecret
					}

					cfg.Strategy = newCfg.Strategy
					log.Println("Configuration reloaded from settings.yaml")

					// Update TokenManager strategy
					tm.SetStrategy(cfg.Strategy.Type)
					// Update TokenManager accounts (reload accounts)
					tm.UpdateAccounts(cfg.Accounts)
				}

				c.JSON(http.StatusOK, gin.H{"status": "updated"})
			})

			// Google Accounts Management
			uiAdmin.GET("/accounts", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"accounts": cfg.Accounts})
			})

			uiAdmin.POST("/accounts", func(c *gin.Context) {
				var req struct {
					Email        string `json:"email"`
					RefreshToken string `json:"refresh_token"`
				}
				if err := c.BindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
					return
				}

				if req.Email == "" || req.RefreshToken == "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Email and Refresh Token are required"})
					return
				}

				if err := config.AddOrUpdateAccount("settings.yaml", req.Email, req.RefreshToken); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}

				// Reload config
				newCfg, err := config.LoadConfig("settings.yaml")
				if err == nil {
					cfg.Accounts = newCfg.Accounts
					tm.UpdateAccounts(cfg.Accounts)
				}

				c.JSON(http.StatusOK, gin.H{"status": "added", "email": req.Email})
			})

			uiAdmin.DELETE("/accounts/:email", func(c *gin.Context) {
				email := c.Param("email")
				if err := config.RemoveAccount("settings.yaml", email); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}

				// Reload config
				newCfg, err := config.LoadConfig("settings.yaml")
				if err == nil {
					cfg.Accounts = newCfg.Accounts
					tm.UpdateAccounts(cfg.Accounts)
				}

				c.JSON(http.StatusOK, gin.H{"status": "deleted"})
			})

			// API Key Management Handlers
			uiAdmin.GET("/keys", func(c *gin.Context) {
				keys, err := database.GetAPIKeys()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				if keys == nil {
					keys = []database.APIKey{}
				}
				c.JSON(http.StatusOK, gin.H{"keys": keys})
			})

			uiAdmin.POST("/keys", func(c *gin.Context) {
				var req struct {
					Name      string `json:"name"`
					ExpiresIn string `json:"expires_in"` // "1h", "24h", "7d", "30d"
					ExpiresAt string `json:"expires_at"` // ISO string for custom date
				}
				if err := c.BindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
					return
				}

				// Calculate expiration
				var expiresAtParams *time.Time

				// 1. Check for specific date (Custom)
				if req.ExpiresAt != "" {
					parsedTime, err := time.Parse(time.RFC3339, req.ExpiresAt)
					if err != nil {
						// Try slightly more lenient parsing if needed, or just strict ISO
						c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format. Use ISO 8601/RFC3339"})
						return
					}
					if parsedTime.Before(time.Now()) {
						c.JSON(http.StatusBadRequest, gin.H{"error": "Expiration date must be in the future"})
						return
					}
					expiresAtParams = &parsedTime
				} else if req.ExpiresIn != "" && req.ExpiresIn != "never" {
					// 2. Check for duration
					var duration time.Duration
					switch req.ExpiresIn {
					case "1h":
						duration = 1 * time.Hour
					case "24h":
						duration = 24 * time.Hour
					case "7d":
						duration = 7 * 24 * time.Hour
					case "30d":
						duration = 30 * 24 * time.Hour
					default:
						if d, err := time.ParseDuration(req.ExpiresIn); err == nil {
							duration = d
						}
					}

					if duration > 0 {
						t := time.Now().Add(duration)
						expiresAtParams = &t
					}
				}

				// Generate random key
				bytes := make([]byte, 24)
				if _, err := crand.Read(bytes); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate key"})
					return
				}
				key := "sk-" + hex.EncodeToString(bytes)

				if err := database.CreateAPIKey(key, 0, req.Name, expiresAtParams); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}

				c.JSON(http.StatusOK, gin.H{"key": key, "name": req.Name, "expires_at": expiresAtParams})
			})

			uiAdmin.DELETE("/keys/:key", func(c *gin.Context) {
				key := c.Param("key")
				if err := database.DeleteAPIKey(key); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"status": "deleted"})
			})

			// ---------------------------------------

			uiPort := 8046
			uiHost := cfg.Server.Host
			if uiHost == "" {
				uiHost = "127.0.0.1" // Default safety
			}
			addr := fmt.Sprintf("%s:%d", uiHost, uiPort)
			log.Printf("Web UI started on http://%s:%d", uiHost, uiPort)
			if err := uiRouter.Run(addr); err != nil {
				log.Printf("Failed to start Web UI: %v", err)
			}
		}()
	}

	// Shared Handlers
	chatHandler := chatCompletionsHandler(tm, up, cfg)
	// anthropicHandler definition moved to top of main
	// modelsHandler definition moved to top of main to support WebUI usage

	geminiHandler := func(c *gin.Context) {
		var trace strings.Builder
		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("=== INCOMING REQUEST (%s) ===\n", time.Now().Format(time.RFC3339)))
			trace.WriteString(fmt.Sprintf("Path: %s\n", c.Request.URL.Path))
		}
		defer func() {
			if cfg.Proxy.Debug && trace.Len() > 0 {
				writeTraceLog(&trace, "trace_gemini")
			}
		}()

		modelParam := c.Param("model")
		isStream := false
		requestedModel := modelParam

		// Handle suffixes
		if strings.HasSuffix(modelParam, ":streamGenerateContent") {
			requestedModel = strings.TrimSuffix(modelParam, ":streamGenerateContent")
			isStream = true
		} else if strings.HasSuffix(modelParam, ":generateContent") {
			requestedModel = strings.TrimSuffix(modelParam, ":generateContent")
		}

		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("Requested Model: %s\n", requestedModel))
		}

		modelCacheMu.RLock()
		model := resolveModel(requestedModel, cfg)
		modelCacheMu.RUnlock()

		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("Resolved Model: %s\n", model))
		}

		body, _ := io.ReadAll(c.Request.Body)
		if cfg.Proxy.Debug {
			trace.WriteString("\n=== REQUEST BODY ===\n")
			trace.Write(body)
			trace.WriteString("\n")
		}

		var geminiReq map[string]interface{}
		json.Unmarshal(body, &geminiReq)

		// Fix for "Please use a valid role" error
		if contents, ok := geminiReq["contents"].([]interface{}); ok {
			for i, c := range contents {
				if contentMap, ok := c.(map[string]interface{}); ok {
					if _, hasRole := contentMap["role"]; !hasRole {
						contentMap["role"] = "user" // Default to user if missing
						contents[i] = contentMap
					}
				}
			}
			geminiReq["contents"] = contents
		}

		if isStream {
			// Capture full response
			var fullResponse strings.Builder

			executeStreamWithRetry(c, tm, up, model, geminiReq, cfg, &trace, func(line string) (string, bool) {
				if strings.HasPrefix(line, "data: ") {
					// Capture content from Gemini stream line (usually "data: " + JSON)
					// Simple capture: just append the line or try to parse text?
					// Gemini SSE data is valid JSON.
					jsonStr := strings.TrimPrefix(line, "data: ")
					var chunk struct {
						Candidates []struct {
							Content struct {
								Parts []struct {
									Text string `json:"text"`
								} `json:"parts"`
							} `json:"content"`
						} `json:"candidates"`
					}
					if json.Unmarshal([]byte(jsonStr), &chunk) == nil && len(chunk.Candidates) > 0 {
						if len(chunk.Candidates[0].Content.Parts) > 0 {
							fullResponse.WriteString(chunk.Candidates[0].Content.Parts[0].Text)
						}
					}

					return line + "\n\n", true
				}
				return "", false
			})

			// Log Streaming Request (Async)
			go func() {
				var prompt string
				if contents, ok := geminiReq["contents"].([]interface{}); ok && len(contents) > 0 {
					if lastContent, ok := contents[len(contents)-1].(map[string]interface{}); ok {
						if parts, ok := lastContent["parts"].([]interface{}); ok && len(parts) > 0 {
							if section, ok := parts[0].(map[string]interface{}); ok {
								if text, ok := section["text"].(string); ok {
									prompt = text
								}
							}
						}
					}
				}

				userID := c.ClientIP()
				if val, exists := c.Get("userID"); exists && val != "" {
					userID = val.(string)
				}

				sessionID, _ := c.Cookie("antimatter_session")

				database.LogRequest(context.Background(), &database.RequestLog{
					Model:     model,
					UserID:    userID,
					SessionID: sessionID,
					Status:    200,
					LatencyMS: 0,
					Prompt:    prompt,
					Response:  fullResponse.String(),
				})
			}()
		} else {
			executeWithRetry(c, tm, up, model, geminiReq, cfg, &trace, func(resp []byte) interface{} {
				var out interface{}
				json.Unmarshal(resp, &out)

				// Log Request (Gemini)
				go func() {
					var prompt string
					if contents, ok := geminiReq["contents"].([]interface{}); ok && len(contents) > 0 {
						if lastContent, ok := contents[len(contents)-1].(map[string]interface{}); ok {
							if parts, ok := lastContent["parts"].([]interface{}); ok && len(parts) > 0 {
								if section, ok := parts[0].(map[string]interface{}); ok {
									if text, ok := section["text"].(string); ok {
										prompt = text
									}
								}
							}
						}
					}

					// Get UserID
					userID := c.ClientIP()
					if val, exists := c.Get("userID"); exists && val != "" {
						userID = val.(string)
					}

					sessionID, _ := c.Cookie("antimatter_session")

					// Extract response text
					var responseText string
					if m, ok := out.(map[string]interface{}); ok {
						if candidates, ok := m["candidates"].([]interface{}); ok && len(candidates) > 0 {
							if cand, ok := candidates[0].(map[string]interface{}); ok {
								if content, ok := cand["content"].(map[string]interface{}); ok {
									if parts, ok := content["parts"].([]interface{}); ok && len(parts) > 0 {
										if part, ok := parts[0].(map[string]interface{}); ok {
											if text, ok := part["text"].(string); ok {
												responseText = text
											}
										}
									}
								}
							}
						}
					}

					// Approximate tokens since Gemini might not return usage in standard response body for all endpoints?
					// Actually we need usage from response if possible.
					// For now, logging basic info.
					database.LogRequest(context.Background(), &database.RequestLog{
						Model:     model,
						UserID:    userID,
						SessionID: sessionID,
						Status:    200,
						LatencyMS: 0, // Should measure logic time
						Prompt:    prompt,
						Response:  responseText,
					})
				}()

				if m, ok := out.(map[string]interface{}); ok {
					if inner, ok := m["response"]; ok {
						return inner
					}
				}
				return out
			})
		}
	}

	// OpenAI Format & Aliases
	r.POST("/v1/chat/completions", chatHandler)
	r.POST("/chat/completions", chatHandler) // Alias without /v1
	r.POST("/v1/responses", chatHandler)     // Alias for specific tools
	r.POST("/responses", chatHandler)        // Alias for specific tools

	// Admin API
	admin := r.Group("/api/admin")

	admin.GET("/captcha", func(c *gin.Context) {
		a := rand.Intn(9) + 1
		b := rand.Intn(9) + 1
		answer := strconv.Itoa(a + b)
		id := uuid.New().String()

		captchaMu.Lock()
		captchaStore[id] = answer
		captchaMu.Unlock()

		// Cleanup old captchas (simple logic: random cleanup or background job)
		// For now simple random cleanup to avoid leak
		if len(captchaStore) > 100 {
			go func() {
				captchaMu.Lock()
				for k := range captchaStore {
					delete(captchaStore, k)
					if len(captchaStore) < 50 {
						break
					}
				}
				captchaMu.Unlock()
			}()
		}

		c.JSON(http.StatusOK, gin.H{
			"id":       id,
			"question": fmt.Sprintf("%d + %d = ?", a, b),
		})
	})

	admin.POST("/login", func(c *gin.Context) {
		ip := c.ClientIP()

		// 1. Check if banned
		banned, reason, err := database.IsBanned(ip)
		if err != nil {
			log.Printf("DB Error checking ban: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal error"})
			return
		}
		if banned {
			c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("IP Banned: %s", reason)})
			return
		}

		// 2. Check failure count
		failCount, err := database.GetFailureCount(ip)
		if err != nil {
			log.Printf("DB Error checking failures: %v", err)
		}

		var req struct {
			Password      string `json:"password"`
			CaptchaId     string `json:"captcha_id"`
			CaptchaAnswer string `json:"captcha_answer"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// 3. Require Captcha if failures >= 5
		if failCount >= 5 {
			if req.CaptchaId == "" || req.CaptchaAnswer == "" {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "Captcha required", "captcha_required": true})
				return
			}

			captchaMu.RLock()
			expected, exists := captchaStore[req.CaptchaId]
			captchaMu.RUnlock()

			if !exists || expected != req.CaptchaAnswer {
				database.IncrementFailure(ip)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Captcha", "captcha_required": true})
				return
			}
			// Captcha ok, consume it
			captchaMu.Lock()
			delete(captchaStore, req.CaptchaId)
			captchaMu.Unlock()
		}

		// Trim input password
		req.Password = strings.TrimSpace(req.Password)

		if req.Password == cfg.Admin.Password && cfg.Admin.Enabled {
			// Success
			database.ResetFailure(ip)

			// Generate JWT
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"authorized": true,
				"exp":        time.Now().Add(24 * time.Hour).Unix(),
				"iat":        time.Now().Unix(),
			})

			// Use the secret key
			reqKey := cfg.Admin.JWTSecret
			if reqKey == "" {
				reqKey = "default-secret-change-me"
			}

			tokenString, err := token.SignedString([]byte(reqKey))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate session"})
				return
			}

			c.SetCookie("admin_session", tokenString, 3600*24, "/", "", false, true)
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		} else {
			// Failure
			newCount, _ := database.IncrementFailure(ip)
			if newCount >= 10 {
				database.BanIP(ip, "Too many failed login attempts")
				c.JSON(http.StatusForbidden, gin.H{"error": "Too many attempts. IP Banned."})
			} else if newCount >= 5 {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password", "captcha_required": true})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
			}
		}
	})

	admin.Use(AdminMiddleware(cfg))
	admin.GET("/stats", func(c *gin.Context) {
		stats, err := database.GetUsageStats()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, stats)
	})

	admin.GET("/logs", func(c *gin.Context) {
		logs, err := database.GetRecentLogs(100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": logs})
	})

	r.POST("/v1/completions", func(c *gin.Context) {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "v1/completions not fully implemented, use v1/chat/completions"})
	})

	// Models list & Aliases
	r.GET("/v1/models", modelsHandler)
	r.GET("/models", modelsHandler) // Alias without /v1

	// Anthropic Format
	r.POST("/v1/messages", anthropicHandler)
	r.POST("/messages", anthropicHandler) // Alias without /v1

	// Gemini Native Format (v1beta)
	r.POST("/v1beta/models/:model", geminiHandler)
	r.POST("/models/:model", geminiHandler) // Alias without /v1beta

	// Health Check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// If AllowLANAccess is false, force host to localhost/127.0.0.1
	// regardless of what might be in Server.Host config if it was set to 0.0.0.0
	// But if config has a specific IP (like 192.168...), should we respect it?
	// The user requirement is: "If allow_lan_access false, CANNOT be reached via 127.0.0.1??". Use interpreting as "CANNOT be reached via external network" (Strict Localhost).
	host := cfg.Server.Host
	if host == "" {
		host = "127.0.0.1" // Default safety
	}

	addr := fmt.Sprintf("%s:%d", host, cfg.Server.Port)
	log.Printf("Antigravity Proxy (Go) started on %s:%d (Strategy: %s)", host, cfg.Server.Port, cfg.Strategy.Type)
	r.Run(addr)
}

func runStatus() {
	tm := auth.NewTokenManager("round-robin")
	up := upstream.NewClient()

	// Temporarily redirect log to discard to keep output clean
	log.SetOutput(io.Discard)

	// Load config for status
	cfg, err := config.LoadConfig("settings.yaml")
	if err == nil {
		for _, acc := range cfg.Accounts {
			tm.AddAccount(acc.Email, acc.RefreshToken, acc.Disabled, acc.DisabledAt, acc.DisabledReason)
		}
	}

	accounts := tm.GetAccounts()

	// Restore log output to stderr
	log.SetOutput(os.Stderr)

	if len(accounts) == 0 {
		fmt.Println("No accounts found in settings.yaml")
		return
	}

	fmt.Printf("Checking status for %d accounts...\n\n", len(accounts))

	for i, acc := range accounts {
		if acc.Disabled {
			fmt.Printf("=== Account [%d/%d]: %s (DISABLED) ===\n", i+1, len(accounts), acc.Email)
			fmt.Printf("Reason: %s\n", acc.DisabledReason)
			fmt.Printf("Disabled At: %s\n\n", time.Unix(acc.DisabledAt, 0).Format(time.RFC1123))
			continue
		}

		if err := tm.RefreshToken(acc); err != nil {
			fmt.Printf("=== Account [%d/%d]: %s ===\n", i+1, len(accounts), acc.Email)
			fmt.Printf("Error: Failed to refresh token: %v\n\n", err)
			continue
		}

		// Get Project ID and Tier
		pid, tier, err := up.FetchProjectDetails(acc.Token.AccessToken)
		if err != nil {
			fmt.Printf("=== Account [%d/%d]: %s ===\n", i+1, len(accounts), acc.Email)
			fmt.Printf("Error: Failed to fetch Project ID: %v\n\n", err)
			continue
		}

		// Map complex tier IDs to readable names if needed
		displayTier := tier
		if tier == "gemini_advanced" {
			displayTier = "Gemini Advanced"
		} else if tier == "standard" {
			displayTier = "Standard"
		}

		fmt.Printf("=== Account [%d/%d]: %s (%s) ===\n", i+1, len(accounts), acc.Email, displayTier)

		models, err := up.FetchQuota(acc.Token.AccessToken, pid)
		if err != nil {
			fmt.Printf("Error: Failed to fetch quota: %v\n\n", err)
			continue
		}

		// Display all models with detailed info
		if len(models) == 0 {
			fmt.Println("No models available.")
		} else {
			fmt.Printf("%-30s | %-10s | %-25s\n", "Model Name", "Remaining", "Next Reset")
			fmt.Println(strings.Repeat("-", 70))

			for name, info := range models {
				if info.QuotaInfo == nil {
					continue
				}

				rem := 0.0
				if info.QuotaInfo.RemainingFraction > 0 {
					rem = info.QuotaInfo.RemainingFraction * 100
				}

				resetTimeStr := info.QuotaInfo.ResetTime
				if resetTimeStr != "" {
					if t, err := time.Parse(time.RFC3339, resetTimeStr); err == nil {
						dur := time.Until(t).Round(time.Minute)
						if dur > 0 {
							h := int(dur.Hours())
							m := int(dur.Minutes()) % 60
							if h >= 24 {
								resetTimeStr = fmt.Sprintf("in %dd %dh", h/24, h%24)
							} else if h > 0 {
								resetTimeStr = fmt.Sprintf("in %dh %dm", h, m)
							} else {
								resetTimeStr = fmt.Sprintf("in %dm", m)
							}
						} else {
							resetTimeStr = "Now"
						}
					}
				} else {
					resetTimeStr = "N/A"
				}

				fmt.Printf("%-30s | %9.2f%% | %-25s\n", name, rem, resetTimeStr)
			}
		}
		fmt.Println()
	}
}

func writeTraceLog(sb *strings.Builder, prefix string) {
	filename := fmt.Sprintf("%s_%d.log", prefix, time.Now().UnixNano())
	if err := os.WriteFile(filename, []byte(sb.String()), 0644); err != nil {
		log.Printf("Failed to write trace log %s: %v", filename, err)
	} else {
		log.Printf("Trace log written to %s", filename)
	}
}

func executeWithRetry(c *gin.Context, tm *auth.TokenManager, up *upstream.Client, model string, geminiReq interface{}, cfg *config.Config, trace *strings.Builder, transform func([]byte) interface{}) {
	var lastErr error
	maxAttempts := 3

	if cfg.Proxy.Debug {
		trace.WriteString("\n=== OUTGOING GEMINI REQUEST (Inner) ===\n")
		reqBytes, _ := json.MarshalIndent(geminiReq, "", "  ")
		trace.Write(reqBytes)
		trace.WriteString("\n\n")
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		acc, err := tm.GetToken()
		if err != nil {
			msg := fmt.Sprintf("no accounts available: %v", err)
			if cfg.Proxy.Debug {
				trace.WriteString(fmt.Sprintf("=== ATTEMPT %d ERROR ===\n%s\n", attempt+1, msg))
			}
			lastErr = fmt.Errorf(msg)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("=== ATTEMPT %d ===\nAccount: %s\n", attempt+1, acc.Email))
		}

		// GenerateContent signature: (accessToken, projectID, model string, requestBody interface{}) ([]byte, error)
		respBody, err := up.GenerateContent(acc.Token.AccessToken, acc.ProjectID, model, geminiReq)
		if err != nil {
			// Upstream client handles retries for rate limits internally.
			// If it returns error, it's likely final or all retries failed.
			msg := fmt.Sprintf("upstream error: %v", err)
			if cfg.Proxy.Debug {
				trace.WriteString(fmt.Sprintf("Error: %s\n", msg))
			}
			lastErr = fmt.Errorf(msg)

			// If it was a rate limit that exhausted retries, we should rotate.
			// The client.go retries on 429. If it failed, it means we are stuck.
			// Inspect error string is brittle, but safer to rotate on any upstream error.
			tm.OnFailure()
			continue
		}

		// Success (Client checks 200 OK)
		out := transform(respBody)
		c.JSON(http.StatusOK, out)
		return
	}

	c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("All attempts failed. Last error: %v", lastErr)})
}

func executeStreamWithRetry(c *gin.Context, tm *auth.TokenManager, up *upstream.Client, model string, geminiReq interface{}, cfg *config.Config, trace *strings.Builder, transform func(string) (string, bool)) {
	// ... (Implementation for stream retry logic similar to standard, but handling SSE)
	// For brevity, using simpler single-shot flow or check existing stream impl.
	// Since we need to support full stream, we'd need a separate loop.
	// Assuming existing executeStreamWithRetry is sufficient or needs sync.
	// In the original file, this function existed. I should preserve it.
	// RE-INSERTING THE ORIGINAL STREAM LOGIC HERE:

	var lastErr error
	maxAttempts := 3

	if cfg.Proxy.Debug {
		trace.WriteString("\n=== OUTGOING GEMINI REQUEST (Stream) ===\n")
		reqBytes, _ := json.MarshalIndent(geminiReq, "", "  ")
		trace.Write(reqBytes)
		trace.WriteString("\n\n")
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Transfer-Encoding", "chunked")

	for attempt := 0; attempt < maxAttempts; attempt++ {
		acc, err := tm.GetToken()
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("=== STREAM ATTEMPT %d (Account: %s) ===\n", attempt+1, acc.Email))
		}

		// StreamGenerateContent returns (io.ReadCloser, error). If error is nil, stream is open (200 OK).
		respStream, err := up.StreamGenerateContent(acc.Token.AccessToken, acc.ProjectID, model, geminiReq)
		if err != nil {
			lastErr = err
			tm.OnFailure()
			continue
		}
		defer respStream.Close()

		// Success - Stream back
		reader := bufio.NewReader(respStream)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					c.Writer.WriteString("data: [DONE]\n\n")
					c.Writer.Flush()
					return
				}
				break
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if transformed, ok := transform(line); ok {
				c.Writer.WriteString(transformed)
				c.Writer.Flush()
			}
		}
		return
	}

	c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("Stream failed: %v", lastErr)})
}
