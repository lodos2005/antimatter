package main

import (
	"antigravity-proxy-go/internal/auth"
	"antigravity-proxy-go/internal/config"
	"antigravity-proxy-go/internal/mappers"
	"antigravity-proxy-go/internal/upstream"
	"bufio"
	"context"
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

	"antigravity-proxy-go/internal/database"

	"github.com/dchest/captcha"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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
			if cfg.Proxy.AllowLanAccess {
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
		if len(cfg.Proxy.ApiKeys) == 0 && mode != "strict" {
			c.Next()
			return
		}

		if mode == "all_except_health" && (c.Request.URL.Path == "/healthz" || c.Request.URL.Path == "/v1/models") {
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
		if len(cfg.Proxy.ApiKeys) > 0 {
			for _, k := range cfg.Proxy.ApiKeys {
				if apiKey == k {
					authorized = true
					break
				}
			}
		} else {
			// If no keys configured but auth is enabled, access is denied.
		}

		if !authorized {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		c.Set("userID", apiKey)
		c.Next()
	}
}

func AdminMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.Admin.Enabled {
			// Validate JWT
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

			// CSRF Check for mutating requests
			if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "DELETE" {
				csrfCookie, _ := c.Cookie("csrf_token")
				csrfHeader := c.GetHeader("X-CSRF-Token")
				if csrfCookie == "" || csrfHeader == "" || csrfCookie != csrfHeader {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "CSRF token mismatch"})
					return
				}
			}

			c.Next()
		} else {
			// If admin is disabled, block access
			c.AbortWithStatus(http.StatusForbidden)
		}
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

		modelCacheMu.RLock()
		model := resolveModel(requestedModel, cfg)
		modelCacheMu.RUnlock()

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
				if choices, ok := out["choices"].([]interface{}); ok && len(choices) > 0 {
					if choice, ok := choices[0].(map[string]interface{}); ok {
						if msg, ok := choice["message"].(map[string]interface{}); ok {
							if content, ok := msg["content"].(string); ok {
								responseText = content
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
		cfg.Proxy.AuthMode = "off"
		cfg.Models.FallbackModel = "gemini-3-flash"
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
	}

	// Check for webui flag
	enableWebUI := false
	for _, arg := range os.Args {
		if arg == "webui" {
			enableWebUI = true
		}
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
		// Always generate a new session ID on refresh/load
		newSessionID := uuid.New().String()
		// Set cookie: name, value, maxAge (0=session), path, domain, secure, httpOnly
		c.SetCookie("antimatter_session", newSessionID, 0, "/", "", false, true)
		c.File("./web/index.html")
	}
	r.GET("/index.html", indexHandler)
	r.StaticFile("/admin.html", "./web/admin.html")
	r.GET("/", indexHandler)

	// Optional Separate WebUI Port (8046) - kept for backward compat if needed, but redundant now
	if enableWebUI {
		go func() {
			uiRouter := gin.Default()
			// Serve static files
			uiRouter.Static("/static", "./web/static")
			uiRouter.StaticFile("/index.html", "./web/index.html")
			uiRouter.StaticFile("/admin.html", "./web/admin.html")
			uiRouter.GET("/", func(c *gin.Context) {
				// Always generate a new session ID on refresh/load
				newSessionID := uuid.New().String()
				// Set cookie: name, value, maxAge (0=session), path, domain, secure, httpOnly
				c.SetCookie("antimatter_session", newSessionID, 0, "/", "", false, true)
				c.File("./web/index.html")
			})

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
				c.JSON(http.StatusOK, gin.H{"data": logs})
			})

			// ---------------------------------------

			uiPort := 8046
			uiHost := cfg.Server.Host
			if uiHost == "" {
				uiHost = "localhost"
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
			finalModels = append(finalModels, m)
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

		if req.Password == cfg.Admin.Password && cfg.Admin.Enabled {
			// Success
			database.ResetFailure(ip)
			c.SetCookie("admin_session", "authenticated", 3600*24, "/", "", false, true)
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

	host := cfg.Server.Host
	if host == "" {
		host = "localhost"
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
