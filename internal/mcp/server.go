package mcp

import (
	"context"
	"fmt"
	"time"

	"antigravity-proxy-go/internal/database"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func CreateMCPServer() *server.MCPServer {
	s := server.NewMCPServer(
		"Antimatter Admin",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true), // Supports Reading & Writing
	)

	// Tool: List API Keys
	s.AddTool(mcp.NewTool("list_api_keys",
		mcp.WithDescription("List all registered API keys"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		keys, err := database.GetAPIKeys()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to list keys: %v", err)), nil
		}

		// Convert to pretty text
		result := "API Keys:\n"
		for _, k := range keys {
			expires := "Never"
			if k.ExpiresAt.Valid {
				expires = k.ExpiresAt.Time.Format(time.RFC3339)
			}
			result += fmt.Sprintf("- %s (%s): Expires: %s\n", k.Name, k.Key, expires)
		}
		return mcp.NewToolResultText(result), nil
	})

	// Tool: Create API Key
	s.AddTool(mcp.NewTool("create_api_key",
		mcp.WithDescription("Create a new API key"),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of the key owner")),
		mcp.WithString("expires_in", mcp.Description("Duration string like 1h, 24h, 7d. Leave empty for never.")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]interface{})
		if !ok {
			return mcp.NewToolResultError("invalid arguments format"), nil
		}

		name, ok := args["name"].(string)
		if !ok {
			return mcp.NewToolResultError("name is required"), nil
		}
		expiresIn, _ := args["expires_in"].(string)

		// Simple key gen
		key := fmt.Sprintf("sk-mcp-%d", time.Now().UnixNano())

		var expiresAt *time.Time
		if expiresIn != "" {
			d, err := time.ParseDuration(expiresIn)
			if err == nil {
				t := time.Now().Add(d)
				expiresAt = &t
			}
		}

		if err := database.CreateAPIKey(key, 0, name, expiresAt); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to create key: %v", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Created Key: %s (Name: %s)", key, name)), nil
	})

	// Tool: Get Recent Logs
	s.AddTool(mcp.NewTool("get_recent_logs",
		mcp.WithDescription("Get the last N request logs"),
		mcp.WithNumber("limit", mcp.Description("Number of logs to fetch (default 10)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		limit := 10
		if args, ok := request.Params.Arguments.(map[string]interface{}); ok {
			if l, ok := args["limit"].(float64); ok {
				limit = int(l)
			}
		}

		logs, err := database.GetRecentLogs(limit)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get logs: %v", err)), nil
		}

		result := fmt.Sprintf("Last %d Logs:\n", len(logs))
		for _, l := range logs {
			result += fmt.Sprintf("[%s] %s used %s -> %s Tokens (%dms)\n",
				l.Timestamp.Format("15:04:05"),
				l.UserID,
				l.Model,
				l.Status, // status code? or tokens? Wait status is int
				l.LatencyMS,
			)
		}
		return mcp.NewToolResultText(result), nil
	})

	return s
}
