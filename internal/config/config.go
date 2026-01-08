package config

import (
	"fmt"
	"os"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

type AccountConfig struct {
	Email          string `yaml:"email"`
	RefreshToken   string `yaml:"refresh_token"`
	Disabled       bool   `yaml:"disabled,omitempty"`
	DisabledAt     int64  `yaml:"disabled_at,omitempty"`
	DisabledReason string `yaml:"disabled_reason,omitempty"`
}

type ProxyConfig struct {
	ApiKeys        []string `yaml:"api_keys"`
	AuthMode       string   `yaml:"auth_mode"` // off, strict, all_except_health, auto
	AllowLanAccess bool     `yaml:"allow_lan_access"`
	Debug          bool     `yaml:"debug"`
}

type ModelsConfig struct {
	FallbackModel string `yaml:"fallback_model"`
}

type Config struct {
	Server struct {
		Port int `yaml:"port"`
	} `yaml:"server"`
	Proxy    ProxyConfig     `yaml:"proxy"`
	Models   ModelsConfig    `yaml:"models"`
	Strategy struct {
		Type string `yaml:"type"`
	} `yaml:"strategy"`
	Accounts []AccountConfig `yaml:"accounts"`
}

func LoadConfig(path string) (*Config, error) {
	// Defaults
	cfg := &Config{}
	cfg.Server.Port = 8045
	cfg.Proxy.AuthMode = "off"
	cfg.Models.FallbackModel = "gemini-3-flash"
	cfg.Strategy.Type = "round-robin"
	cfg.Accounts = []AccountConfig{}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Create example file
			if err := createExampleConfig(path); err != nil {
				return nil, err
			}
			return cfg, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func createExampleConfig(path string) error {
	example := `# Antimatter Proxy Configuration
server:
  port: 8045

proxy:
  # List of API keys that can access the proxy. If empty, anyone can access (unless mode=strict).
  api_keys:
    # - "sk-your-secret-key"
  
  # Auth mode: 
  #   - off: No auth required (default).
  #   - strict: Auth required for all routes.
  #   - all_except_health: Auth required for all except /healthz and /v1/models.
  #   - auto: 'off' locally, 'all_except_health' if allow_lan_access is true.
  auth_mode: "off"
  
  # Allow LAN access (binds to 0.0.0.0 instead of 127.0.0.1)
  allow_lan_access: false

  # Enable debug mode to write detailed request/response trace logs to disk
  debug: false

models:
  # Model used when the requested model is not recognized or not available
  fallback_model: "gemini-3-flash"

# Account selection strategy
# options: 
#   - round-robin: Rotate accounts with every request (default). Distributes load evenly.
#   - sequential: Use the first account until it fails (429/401), then switch to the next.
strategy:
  type: round-robin

accounts:
  # - email: "example@gmail.com"
  #   refresh_token: "YOUR_REFRESH_TOKEN_HERE"
`
	return os.WriteFile(path, []byte(example), 0644)
}

func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// AddOrUpdateAccount adds or updates an account in settings.yaml without losing comments.
func AddOrUpdateAccount(pathStr string, email string, refreshToken string) error {
	data, err := os.ReadFile(pathStr)
	if err != nil {
		return err
	}

	file, err := parser.ParseBytes(data, parser.ParseComments)
	if err != nil {
		return err
	}

	if len(file.Docs) == 0 {
		return fmt.Errorf("empty config file")
	}

	body, ok := file.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return fmt.Errorf("config root is not a mapping")
	}

	var accountsKV *ast.MappingValueNode
	for _, kv := range body.Values {
		if k, ok := kv.Key.(*ast.StringNode); ok && k.Value == "accounts" {
			accountsKV = kv
			break
		}
	}

	// 1. If "accounts" key doesn't exist, append it.
	if accountsKV == nil {
		f, err := os.OpenFile(pathStr, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		
		// Ensure newline if needed
		if len(data) > 0 && data[len(data)-1] != '\n' {
			f.WriteString("\n")
		}
		
		if _, err := f.WriteString(fmt.Sprintf("accounts:\n  - email: %q\n    refresh_token: %q\n", email, refreshToken)); err != nil {
			return err
		}
		return nil
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

				if err := updateOrAppend("disabled", "true"); err != nil { return err }
				if err := updateOrAppend("disabled_at", fmt.Sprintf("%d", time.Now().Unix())); err != nil { return err }
				if err := updateOrAppend("disabled_reason", fmt.Sprintf("%q", reason)); err != nil { return err }

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
