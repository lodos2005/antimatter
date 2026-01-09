package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

type AccountConfig struct {
	Email          string `yaml:"email" json:"email"`
	RefreshToken   string `yaml:"refresh_token" json:"refresh_token"`
	Disabled       bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	DisabledAt     int64  `yaml:"disabled_at,omitempty" json:"disabled_at,omitempty"`
	DisabledReason string `yaml:"disabled_reason,omitempty" json:"disabled_reason,omitempty"`
}

type ServerConfig struct {
	Port      int    `yaml:"port" json:"port"`
	WebUIPort int    `yaml:"webui_port" json:"webui_port"`
	Host      string `yaml:"host" json:"host"`
}

type ProxyConfig struct {
	APIKeys  []string `yaml:"api_keys" json:"api_keys"`
	AuthMode string   `yaml:"auth_mode" json:"auth_mode"`
	Debug    bool     `yaml:"debug" json:"debug"`
}

type ModelsConfig struct {
	FallbackModel string `yaml:"fallback_model" json:"fallback_model"`
	SystemPrompt  string `yaml:"system_prompt" json:"system_prompt"`
}

type AdminConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Password  string `yaml:"password" json:"password"` // Encrypted or plain?
	JWTSecret string `yaml:"jwt_secret" json:"jwt_secret"`
}

type MCPConfig struct {
	Mode string `yaml:"mode" json:"mode"` // "off", "server", "provider"
}

type Config struct {
	Server   ServerConfig    `yaml:"server" json:"server"`
	Proxy    ProxyConfig     `yaml:"proxy" json:"proxy"`
	Models   ModelsConfig    `yaml:"models" json:"models"`
	Admin    AdminConfig     `yaml:"admin" json:"admin"`
	MCP      MCPConfig       `yaml:"mcp" json:"mcp"`
	Strategy StrategyConfig  `yaml:"strategy" json:"strategy"`
	Session  SessionConfig   `yaml:"session" json:"session"`
	Accounts []AccountConfig `yaml:"accounts" json:"accounts"`
}

type StrategyConfig struct {
	Type string `yaml:"type" json:"type"`
}

type SessionConfig struct {
	WebUIRequestLimit int `yaml:"webui_request_limit" json:"webui_request_limit"`
	WebUITokenLimit   int `yaml:"webui_token_limit" json:"webui_token_limit"`
}

// LoadConfig loads the configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	// If file doesn't exist, create example
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := createExampleConfig(path); err != nil {
			return nil, fmt.Errorf("failed to create example config: %v", err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		// If unmarshal fails, we might still want to try returning partial config, or just error.
		// For robustness, if new fields like Session are missing in user's old config but present in struct,
		// yaml.Unmarshal usually handles it (zero values).
		return nil, err
	}

	// Ensure positive limit if negative
	if cfg.Session.WebUIRequestLimit < 0 {
		cfg.Session.WebUIRequestLimit = -cfg.Session.WebUIRequestLimit
	}
	if cfg.Session.WebUITokenLimit < 0 {
		cfg.Session.WebUITokenLimit = -cfg.Session.WebUITokenLimit
	}

	// Default System Prompt
	if cfg.Models.SystemPrompt == "" {
		cfg.Models.SystemPrompt = "You are research assistant"
	}

	// Default MCP Mode
	if cfg.MCP.Mode == "" {
		cfg.MCP.Mode = "off"
	}

	return &cfg, nil
}

func createExampleConfig(path string) error {
	content := `# Antimatter Proxy Configuration
server:
  port: 8045
  # Host to bind to. Use "0.0.0.0" for all interfaces, "localhost" for local only,
  # or a specific IP like "192.168.1.100" for a particular network interface
  host: "0.0.0.0"

proxy:
  # List of API keys that can access the proxy. If empty, anyone can access (unless mode=strict).
  api_keys:
    # - "sk-your-secret-key"
  
  # Auth mode: 
  #   - off: No auth required (default).
  #   - strict: Auth required for all routes.
  #   - all_except_health: Auth required for all except /healthz and /v1/models.
  #   - auto: 'off' locally, 'all_except_health' if allow_lan_access is true.
  #   - auto: 'off' locally, 'all_except_health' if host is 0.0.0.0.
  auth_mode: "off"

  # Enable debug mode to write detailed request/response trace logs to disk
  debug: false

models:
  # Model used when the requested model is not recognized or not available
  fallback_model: "gemini-3-flash"
  # Default system prompt for all chat completions
  system_prompt: "You are research assistant"

admin:
  enabled: true
  # Password for accessing the /admin.html panel
  password: "admin"
  jwt_secret: "random"

mcp:
  # Mode: "off" (default), "server" (run MCP server), or "provider" (connect to MCP server)
  mode: "off"

# Account selection strategy
# options: 
#   - round-robin: Rotate accounts with every request (default). Distributes load evenly.
#   - sequential: Use the first account until it fails (429/401), then switch to the next.
strategy:
  type: round-robin

session:
  # Limit number of chat requests per specific WebUI session.
  # 0 = Unlimited. > 0 = Limit.
  webui_request_limit: 50
  # Limit total tokens usage per specific WebUI session.
  # 0 = Unlimited. > 0 = Limit.
  webui_token_limit: 50000

accounts:
  # - email: "example@gmail.com"
  #   refresh_token: "YOUR_REFRESH_TOKEN_HERE"
`
	return os.WriteFile(path, []byte(content), 0644)
}

// AddOrUpdateAccount uses AST parsing to preserve comments while updating accounts
func AddOrUpdateAccount(pathStr string, email, refreshToken string) error {
	data, err := os.ReadFile(pathStr)
	if err != nil {
		return err
	}

	// Parse with ParseComments to preserve them
	file, err := parser.ParseBytes(data, parser.ParseComments)
	if err != nil {
		return err
	}

	// Navigate to $.accounts
	path, err := yaml.PathString("$.accounts")
	if err != nil {
		return err
	}

	// Check if "accounts" node exists
	_, err = path.ReadNode(file)

	// 1. If "accounts" key doesn't exist at all, we'd need to add it to the root mapping.
	// This is slightly complex with just PathString. simpler to verify structure first.
	// Assuming structure exists from LoadConfig/createExampleConfig.
	if err != nil {
		// Try to append "accounts: " to the end of file if missing, then re-parse?
		// Or assume it exists. Let's assume it exists or fail for now.
		return fmt.Errorf("config structure invalid: accounts key missing")
	}

	// Found "accounts", but we need the SequenceNode
	// Note: ReadNode returns the Value node.

	// Handle "accounts: null" (empty in yaml)
	// We need to find the specific MappingValueNode for "accounts" to replace its value if it is null
	// However, path.ReadNode returns the value.

	// Hack: Re-traverse manualy to find the key "accounts" to allow replacing "null" with a sequence
	rootMap, ok := file.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return fmt.Errorf("root is not a mapping")
	}
	var accountsKV *ast.MappingValueNode
	for _, kv := range rootMap.Values {
		if k, ok := kv.Key.(*ast.StringNode); ok && k.Value == "accounts" {
			accountsKV = kv
			break
		}
	}

	if accountsKV == nil {
		// Should have been caught by ReadNode error, but double check
		return fmt.Errorf("accounts key not found in AST")
	}

	// 2. If "accounts" exists but is empty (null), replace with new sequence.
	if _, ok := accountsKV.Value.(*ast.NullNode); ok {
		snippet := fmt.Sprintf("- email: %q\n  refresh_token: %q\n", email, refreshToken)
		snippetFile, err := parser.ParseBytes([]byte(snippet), 0)
		if err != nil {
			return err
		}
		if len(snippetFile.Docs) > 0 {
			if newSeq, ok := snippetFile.Docs[0].Body.(*ast.SequenceNode); ok {
				accountsKV.Value = newSeq
			}
		}
		return os.WriteFile(pathStr, []byte(file.String()), 0644)
	}

	// 3. If "accounts" is a sequence, update or append.
	seq, ok := accountsKV.Value.(*ast.SequenceNode)
	if !ok {
		return fmt.Errorf("accounts is not a list (type: %T)", accountsKV.Value)
	}

	updated := false
	for _, item := range seq.Values {
		if mapping, ok := item.(*ast.MappingNode); ok {
			isTarget := false
			for _, kv := range mapping.Values {
				if k, ok := kv.Key.(*ast.StringNode); ok && k.Value == "email" {
					if v, ok := kv.Value.(*ast.StringNode); ok && v.Value == email {
						isTarget = true
						break
					}
				}
			}

			if isTarget {
				// Update refresh_token
				for _, kv := range mapping.Values {
					if k, ok := kv.Key.(*ast.StringNode); ok && k.Value == "refresh_token" {
						valSnippet := fmt.Sprintf("k: %q", refreshToken)
						valFile, err := parser.ParseBytes([]byte(valSnippet), 0)
						if err == nil && len(valFile.Docs) > 0 {
							if m, ok := valFile.Docs[0].Body.(*ast.MappingNode); ok && len(m.Values) > 0 {
								kv.Value = m.Values[0].Value
								updated = true
							}
						}
						break
					}
				}
				// If refresh_token key missing in existing account, we should add it?
				// Skipping for simplicity, usually it exists.
			}
		}
		if updated {
			break
		}
	}

	if !updated {
		// Append new account
		snippet := fmt.Sprintf("- email: %q\n  refresh_token: %q\n", email, refreshToken)
		snippetFile, err := parser.ParseBytes([]byte(snippet), 0)
		if err == nil {
			if len(snippetFile.Docs) > 0 {
				if newSeq, ok := snippetFile.Docs[0].Body.(*ast.SequenceNode); ok {
					if len(newSeq.Values) > 0 {
						seq.Values = append(seq.Values, newSeq.Values[0])
					}
				}
			}
		}
	}

	return os.WriteFile(pathStr, []byte(file.String()), 0644)
}

// SetAccountDisabled marks an account as disabled in settings.yaml
func SetAccountDisabled(pathStr string, email string, reason string) error {
	data, err := os.ReadFile(pathStr)
	if err != nil {
		return err
	}

	file, err := parser.ParseBytes(data, parser.ParseComments)
	if err != nil {
		return err
	}

	path, err := yaml.PathString("$.accounts")
	if err != nil {
		return err
	}

	node, err := path.ReadNode(file)
	if err != nil {
		return fmt.Errorf("accounts block not found")
	}

	seq, ok := node.(*ast.SequenceNode)
	if !ok {
		return fmt.Errorf("accounts is not a list")
	}

	updated := false
	for _, item := range seq.Values {
		if mapping, ok := item.(*ast.MappingNode); ok {
			isTarget := false
			for _, kv := range mapping.Values {
				if k, ok := kv.Key.(*ast.StringNode); ok && k.Value == "email" {
					if v, ok := kv.Value.(*ast.StringNode); ok && v.Value == email {
						isTarget = true
						break
					}
				}
			}

			if isTarget {
				// Helper to update or append a key-value pair using parsed snippets
				updateOrAppend := func(key, valSnippet string) error {
					// Parse "key: value" to get a valid MappingValueNode
					snippet := fmt.Sprintf("%s: %s", key, valSnippet)
					f, err := parser.ParseBytes([]byte(snippet), 0)
					if err != nil {
						return err
					}
					if len(f.Docs) == 0 {
						return fmt.Errorf("failed to parse snippet")
					}
					m, ok := f.Docs[0].Body.(*ast.MappingNode)
					if !ok || len(m.Values) == 0 {
						return fmt.Errorf("failed to extract mapping value")
					}
					newKV := m.Values[0]

					found := false
					for _, kv := range mapping.Values {
						if k, ok := kv.Key.(*ast.StringNode); ok && k.Value == key {
							kv.Value = newKV.Value
							found = true
							break
						}
					}
					if !found {
						mapping.Values = append(mapping.Values, newKV)
					}
					return nil
				}

				if err := updateOrAppend("disabled", "true"); err != nil {
					return err
				}
				if err := updateOrAppend("disabled_at", fmt.Sprintf("%d", time.Now().Unix())); err != nil {
					return err
				}
				if err := updateOrAppend("disabled_reason", fmt.Sprintf("%q", reason)); err != nil {
					return err
				}

				updated = true
				break
			}
		}
	}

	if !updated {
		return fmt.Errorf("account not found: %s", email)
	}

	return os.WriteFile(pathStr, []byte(file.String()), 0644)
}

// UpdateSettings updates specific configuration values preserving comments.
// It supports nested keys like "models.system_prompt" and will create missing keys if necessary.
func UpdateSettings(pathStr string, updates map[string]interface{}) error {
	data, err := os.ReadFile(pathStr)
	if err != nil {
		return err
	}

	file, err := parser.ParseBytes(data, parser.ParseComments)
	if err != nil {
		return err
	}

	if len(file.Docs) == 0 {
		return fmt.Errorf("empty yaml file")
	}

	root, ok := file.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return fmt.Errorf("root is not a mapping node")
	}

	for key, val := range updates {
		// Split key into parts (e.g., "models.system_prompt")
		parts := strings.Split(key, ".")

		// Traverse AST and create missing sections if needed
		var currentMap = root
		for i, part := range parts {
			isLast := i == len(parts)-1
			found := false

			// Check if key exists in current mapping
			for _, kv := range currentMap.Values {
				if k, ok := kv.Key.(*ast.StringNode); ok && k.Value == part {
					found = true
					if isLast {
						// Update value
						newNode, err := createValueNode(val)
						if err == nil {
							kv.Value = newNode
						}
					} else {
						// Navigate deeper
						if nextMap, ok := kv.Value.(*ast.MappingNode); ok {
							currentMap = nextMap
						} else if _, ok := kv.Value.(*ast.NullNode); ok {
							// If it's a NullNode, replace it with a new MappingNode
							newMap := &ast.MappingNode{BaseNode: &ast.BaseNode{}}
							kv.Value = newMap
							currentMap = newMap
						} else {
							// Conflict: path part exists but is not a mapping
							found = false // Force creation/overwrite logic if we want, but safer to error
							return fmt.Errorf("config path conflict at %s: %s is not a mapping", key, part)
						}
					}
					break
				}
			}

			if !found {
				// Create new key-value pair using parsing
				if isLast {
					// Last part: create key: value
					newKV, err := createMappingValueNode(part, val)
					if err != nil {
						return fmt.Errorf("failed to create node for %s: %v", key, err)
					}
					currentMap.Values = append(currentMap.Values, newKV)
				} else {
					// Intermediate part: create key: {} and navigate into it
					emptyMapSnippet := fmt.Sprintf("%s: {}", part)
					snippetFile, err := parser.ParseBytes([]byte(emptyMapSnippet), 0)
					if err != nil || len(snippetFile.Docs) == 0 {
						return fmt.Errorf("failed to parse intermediate node for %s", part)
					}
					snippetMap, ok := snippetFile.Docs[0].Body.(*ast.MappingNode)
					if !ok || len(snippetMap.Values) == 0 {
						return fmt.Errorf("failed to extract intermediate node for %s", part)
					}
					newKV := snippetMap.Values[0]
					currentMap.Values = append(currentMap.Values, newKV)

					// Navigate into the newly created map
					if nextMap, ok := newKV.Value.(*ast.MappingNode); ok {
						currentMap = nextMap
					} else {
						return fmt.Errorf("created node for %s is not a mapping", part)
					}
				}
			}
		}
	}

	return os.WriteFile(pathStr, []byte(file.String()), 0644)
}

// createMappingValueNode creates a key-value pair by parsing a YAML snippet
func createMappingValueNode(key string, val interface{}) (*ast.MappingValueNode, error) {
	var valStr string
	switch v := val.(type) {
	case string:
		valStr = fmt.Sprintf("%q", v)
	case int, int64, float64, int32:
		valStr = fmt.Sprintf("%v", v)
	case bool:
		valStr = fmt.Sprintf("%v", v)
	default:
		return nil, fmt.Errorf("unsupported type %T", val)
	}

	snippet := fmt.Sprintf("%s: %s", key, valStr)
	f, err := parser.ParseBytes([]byte(snippet), 0)
	if err != nil || len(f.Docs) == 0 {
		return nil, fmt.Errorf("failed to parse mapping value")
	}
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	if !ok || len(m.Values) == 0 {
		return nil, fmt.Errorf("failed to extract mapping value node")
	}
	return m.Values[0], nil
}

// createValueNode is a helper to turn a Go value into a YAML AST node
func createValueNode(val interface{}) (ast.Node, error) {
	var valStr string
	switch v := val.(type) {
	case string:
		valStr = fmt.Sprintf("%q", v)
	case int, int64, float64, int32:
		valStr = fmt.Sprintf("%v", v)
	case bool:
		valStr = fmt.Sprintf("%v", v)
	default:
		return nil, fmt.Errorf("unsupported type %T", val)
	}

	dummyYAML := fmt.Sprintf("k: %s", valStr)
	f, err := parser.ParseBytes([]byte(dummyYAML), 0)
	if err != nil || len(f.Docs) == 0 {
		return nil, fmt.Errorf("failed to parse value")
	}
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	if !ok || len(m.Values) == 0 {
		return nil, fmt.Errorf("failed to extract value node")
	}
	return m.Values[0].Value, nil
}

// RemoveAccount removes an account by email from settings.yaml while preserving comments
func RemoveAccount(pathStr, email string) error {
	data, err := os.ReadFile(pathStr)
	if err != nil {
		return err
	}

	file, err := parser.ParseBytes(data, parser.ParseComments)
	if err != nil {
		return err
	}

	// Navigate to $.accounts
	path, err := yaml.PathString("$.accounts")
	if err != nil {
		return err
	}

	// Get the accounts node
	node, err := path.ReadNode(file)
	if err != nil {
		return fmt.Errorf("accounts key not found")
	}

	// Ensure it's a sequence
	seq, ok := node.(*ast.SequenceNode)
	if !ok {
		return fmt.Errorf("accounts is not a list")
	}

	// Iterate and find the index to remove
	idxToRemove := -1
	for i, val := range seq.Values {
		// val is likely a MappingNode (the account object)
		mapping, ok := val.(*ast.MappingNode)
		if !ok {
			continue
		}

		// Find email field in this mapping
		for _, kv := range mapping.Values {
			if k, ok := kv.Key.(*ast.StringNode); ok && k.Value == "email" {
				if v, ok := kv.Value.(*ast.StringNode); ok && v.Value == email {
					idxToRemove = i
					break
				}
			}
		}
		if idxToRemove != -1 {
			break
		}
	}

	if idxToRemove == -1 {
		return fmt.Errorf("account not found: %s", email)
	}

	// Remove element at index
	newValues := append(seq.Values[:idxToRemove], seq.Values[idxToRemove+1:]...)
	seq.Values = newValues

	return os.WriteFile(pathStr, []byte(file.String()), 0644)
}
