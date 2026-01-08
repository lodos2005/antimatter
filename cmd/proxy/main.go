package main

import (
	"antigravity-proxy-go/internal/auth"
	"antigravity-proxy-go/internal/config"
	"antigravity-proxy-go/internal/mappers"
	"antigravity-proxy-go/internal/upstream"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	modelCache   []string
	modelCacheMu sync.RWMutex
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
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, x-api-key, anthropic-version")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
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

		modelCacheMu.RLock()
		model := resolveModel(requestedModel, cfg)
		modelCacheMu.RUnlock()

		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("Resolved Model: %s\n", model))
		}

		if req.Stream {
			executeStreamWithRetry(c, tm, up, model, geminiReq, cfg, &trace, func(line string) (string, bool) {
				return mappers.TransformOpenAIStreamChunk(line, model)
			})
		} else {
			executeWithRetry(c, tm, up, model, geminiReq, cfg, &trace, func(resp []byte) interface{} {
				out, _ := mappers.TransformOpenAIResponse(resp, model)
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
	if enableWebUI {
		go func() {
			uiRouter := gin.Default()
			// Serve static files
			uiRouter.Static("/static", "./web/static")
			uiRouter.StaticFile("/index.html", "./web/index.html")
			uiRouter.GET("/", func(c *gin.Context) {
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
			executeStreamWithRetry(c, tm, up, model, geminiReq, cfg, &trace, func(line string) (string, bool) {
				if strings.HasPrefix(line, "data: ") {
					return line + "\n\n", true
				}
				return "", false
			})
		} else {
			executeWithRetry(c, tm, up, model, geminiReq, cfg, &trace, func(resp []byte) interface{} {
				var out interface{}
				json.Unmarshal(resp, &out)
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
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": msg})
			return
		}

		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("=== ATTEMPT %d ===\nAccount: %s\n", attempt+1, acc.Email))
		}

		if acc.ProjectID == "" {
			pid, _, err := up.FetchProjectDetails(acc.Token.AccessToken)
			if err != nil {
				lastErr = err
				tm.OnFailure()
				if cfg.Proxy.Debug {
					trace.WriteString(fmt.Sprintf("Error fetching project ID: %v\n", err))
				}
				log.Printf("Attempt %d failed for %s (Project fetch): %v", attempt+1, acc.Email, err)
				continue
			}
			acc.ProjectID = pid
		}

		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("ProjectID: %s\nModel: %s\n", acc.ProjectID, model))
		}

		resp, err := up.GenerateContent(acc.Token.AccessToken, acc.ProjectID, model, geminiReq)
		if err != nil {
			lastErr = err
			tm.OnFailure()
			if cfg.Proxy.Debug {
				trace.WriteString(fmt.Sprintf("Upstream Error: %v\n", err))
			}
			log.Printf("Attempt %d failed for %s: %v", attempt+1, acc.Email, err)
			continue
		}

		if cfg.Proxy.Debug {
			trace.WriteString("\n=== UPSTREAM RESPONSE ===\n")
			trace.Write(resp)
			trace.WriteString("\n")
		}

		c.JSON(http.StatusOK, transform(resp))
		return
	}

	c.JSON(http.StatusBadGateway, gin.H{"error": lastErr.Error()})
}

func executeStreamWithRetry(c *gin.Context, tm *auth.TokenManager, up *upstream.Client, model string, geminiReq interface{}, cfg *config.Config, trace *strings.Builder, transform func(string) (string, bool)) {
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
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": msg})
			return
		}

		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("=== ATTEMPT %d ===\nAccount: %s\n", attempt+1, acc.Email))
		}

		if acc.ProjectID == "" {
			pid, _, err := up.FetchProjectDetails(acc.Token.AccessToken)
			if err != nil {
				lastErr = err
				tm.OnFailure()
				if cfg.Proxy.Debug {
					trace.WriteString(fmt.Sprintf("Error fetching project ID: %v\n", err))
				}
				log.Printf("Stream attempt %d failed for %s (Project fetch): %v", attempt+1, acc.Email, err)
				continue
			}
			acc.ProjectID = pid
		}

		if cfg.Proxy.Debug {
			trace.WriteString(fmt.Sprintf("ProjectID: %s\nModel: %s\n", acc.ProjectID, model))
		}

		stream, err := up.StreamGenerateContent(acc.Token.AccessToken, acc.ProjectID, model, geminiReq)
		if err != nil {
			lastErr = err
			tm.OnFailure()
			if cfg.Proxy.Debug {
				trace.WriteString(fmt.Sprintf("Upstream Error: %v\n", err))
			}
			log.Printf("Stream attempt %d failed for %s: %v", attempt+1, acc.Email, err)
			continue
		}
		defer stream.Close()

		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		// Flush headers immediately
		c.Writer.Flush()

		if cfg.Proxy.Debug {
			trace.WriteString("\n=== STREAM RESPONSE CHUNKS ===\n")
		}

		scanner := bufio.NewScanner(stream)
		for scanner.Scan() {
			line := scanner.Text()

			if cfg.Proxy.Debug {
				trace.WriteString(line + "\n")
			}

			if out, ok := transform(line); ok {
				c.Writer.WriteString(out)
				c.Writer.Flush()
			}
		}

		if err := scanner.Err(); err != nil {
			if cfg.Proxy.Debug {
				trace.WriteString(fmt.Sprintf("\nStream Read Error: %v\n", err))
			}
			log.Printf("Stream reading error: %v", err)
		}
		return
	}

	c.JSON(http.StatusBadGateway, gin.H{"error": lastErr.Error()})
}
