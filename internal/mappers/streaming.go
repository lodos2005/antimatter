package mappers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func TransformOpenAIStreamChunk(line string, model string) (string, bool) {
	if !strings.HasPrefix(line, "data: ") {
		return "", false
	}

	dataStr := strings.TrimPrefix(line, "data: ")
	if dataStr == "[DONE]" {
		return "data: [DONE]\n\n", true
	}

	var geminiResp map[string]interface{}
	if err := json.Unmarshal([]byte(dataStr), &geminiResp); err != nil {
		return "", false
	}

	// Unwrap v1internal response
	inner, ok := geminiResp["response"].(map[string]interface{})
	if !ok {
		inner = geminiResp
	}

	candidates, _ := inner["candidates"].([]interface{})
	contentStr := ""
	reasoningStr := ""
	finishReason := interface{}(nil)

	if len(candidates) > 0 {
		cand := candidates[0].(map[string]interface{})
		content, _ := cand["content"].(map[string]interface{})
		parts, _ := content["parts"].([]interface{})
		
		for _, p := range parts {
			if part, ok := p.(map[string]interface{}); ok {
				isThought := false
				if th, ok := part["thought"].(bool); ok && th {
					isThought = true
				}

				if t, ok := part["text"].(string); ok {
					if isThought {
						reasoningStr += t
					} else {
						contentStr += t
					}
				}
			}
		}
		finishReason = cand["finishReason"]
	}

	if contentStr == "" && reasoningStr == "" && finishReason == nil {
		return "", false
	}

	delta := map[string]interface{}{}
	if contentStr != "" {
		delta["content"] = contentStr
	}
	if reasoningStr != "" {
		delta["reasoning_content"] = reasoningStr
	}

	openaiChunk := map[string]interface{}{
		"id":      fmt.Sprintf("chatcmpl-%s", uuid.New().String()),
		"object":  "chat.completion.chunk",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]interface{}{
			{
				"index":         0,
				"delta":         delta,
				"finish_reason": finishReason,
			},
		},
	}

	chunkJSON, _ := json.Marshal(openaiChunk)
	return fmt.Sprintf("data: %s\n\n", string(chunkJSON)), true
}
