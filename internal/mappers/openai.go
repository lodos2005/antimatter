package mappers

import (
	"encoding/json"
	"fmt"
	"strings"
)

type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIRequest struct {
	Model    string          `json:"model"`
	Messages []OpenAIMessage `json:"messages"`
}

func TransformOpenAIRequest(body []byte) (map[string]interface{}, string, error) {
	var req OpenAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", err
	}

	contents := []map[string]interface{}{}
	var systemParts []map[string]interface{}

	for _, msg := range req.Messages {
		if msg.Role == "system" {
			systemParts = append(systemParts, map[string]interface{}{
				"text": msg.Content,
			})
			continue
		}

		role := msg.Role
		if role == "assistant" {
			role = "model"
		}

		contents = append(contents, map[string]interface{}{
			"role": role,
			"parts": []map[string]interface{}{
				{"text": msg.Content},
			},
		})
	}

	geminiReq := map[string]interface{}{
		"contents": contents,
		"generationConfig": map[string]interface{}{
			"maxOutputTokens": 8192,
			"temperature":     1.0,
		},
	}

	if len(systemParts) > 0 {
		geminiReq["system_instruction"] = map[string]interface{}{
			"parts": systemParts,
		}
	}

	// Inject thinkingConfig ONLY if model name suggests thinking
	if strings.Contains(req.Model, "thinking") {
		genConfig, _ := geminiReq["generationConfig"].(map[string]interface{})
		genConfig["thinkingConfig"] = map[string]interface{}{
			"includeThoughts": true,
			"thinkingBudget":  16000,
		}
		// Ensure maxOutputTokens is greater than thinkingBudget (16000)
		genConfig["maxOutputTokens"] = 64000
	}

	return geminiReq, req.Model, nil
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

func TransformOpenAIResponse(upstreamBody []byte, model string) (map[string]interface{}, Usage, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(upstreamBody, &data); err != nil {
		return nil, Usage{}, err
	}

	// Unwrap v1internal response
	inner, ok := data["response"].(map[string]interface{})
	if !ok {
		inner = data
	}

	candidates, _ := inner["candidates"].([]interface{})
	contentStr := ""
	thoughtStr := ""

	if len(candidates) > 0 {
		cand := candidates[0].(map[string]interface{})
		content, _ := cand["content"].(map[string]interface{})
		parts, _ := content["parts"].([]interface{})

		for _, p := range parts {
			if part, ok := p.(map[string]interface{}); ok {
				text, _ := part["text"].(string)
				// Check for thought marker (this depends on Gemini API specifics, usually defined by 'thought': true or similar)
				// For 'includeThoughts=true', it often returns a part with thought: true
				isThought := false
				if t, ok := part["thought"].(bool); ok && t {
					isThought = true
				}

				if isThought {
					thoughtStr += text + "\n"
				} else {
					contentStr += text
				}
			}
		}
	}

	// Usage Logic
	usage := Usage{}
	if um, ok := inner["usageMetadata"].(map[string]interface{}); ok {
		if pt, ok := um["promptTokenCount"].(float64); ok {
			usage.PromptTokens = int(pt)
		}
		if ct, ok := um["candidatesTokenCount"].(float64); ok {
			usage.CompletionTokens = int(ct)
		}
		if tt, ok := um["totalTokenCount"].(float64); ok {
			usage.TotalTokens = int(tt)
		}
	}
	// Fallback if total is missing but others exist
	if usage.TotalTokens == 0 {
		usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
	}

	message := map[string]interface{}{
		"role":    "assistant",
		"content": contentStr,
	}
	if thoughtStr != "" {
		message["thought"] = strings.TrimSpace(thoughtStr)
	}

	openaiResp := map[string]interface{}{
		"id":      fmt.Sprintf("chatcmpl-%d", 12345), // Should be more unique
		"object":  "chat.completion",
		"created": 1700000000,
		"model":   model,
		"choices": []map[string]interface{}{
			{
				"index":         0,
				"message":       message,
				"finish_reason": "stop",
			},
		},
		"usage": map[string]interface{}{
			"prompt_tokens":     usage.PromptTokens,
			"completion_tokens": usage.CompletionTokens,
			"total_tokens":      usage.TotalTokens,
		},
	}

	return openaiResp, usage, nil
}
