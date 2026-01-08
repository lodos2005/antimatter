package mappers

import (
	"encoding/json"
)

func TransformAnthropicRequest(body []byte) (map[string]interface{}, string, error) {
	// For basic text messages, the structure is very similar to OpenAI
	// Reuse OpenAI logic for now but adjust model mapping
	req, model, err := TransformOpenAIRequest(body)
	if err != nil {
		return nil, "", err
	}

	// Specific model mapping for Claude
	if model == "gemini-3-pro-high" { // If it was default
		// Map Claude-specific names to Gemini
		var input struct {
			Model string `json:"model"`
		}
		json.Unmarshal(body, &input)
		
		switch input.Model {
		case "claude-3-5-sonnet-20241022", "claude-3-5-sonnet":
			model = "gemini-3-pro-high"
		case "claude-3-opus-20240229":
			model = "gemini-3-pro-high"
		case "claude-3-haiku-20240307":
			model = "gemini-3-flash"
		}
	}

	return req, model, nil
}

func TransformAnthropicResponse(upstreamBody []byte, model string) (map[string]interface{}, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(upstreamBody, &data); err != nil {
		return nil, err
	}

	// Unwrap v1internal response
	inner, ok := data["response"].(map[string]interface{})
	if !ok {
		inner = data
	}

	candidates, _ := inner["candidates"].([]interface{})
	contentStr := ""
	if len(candidates) > 0 {
		cand := candidates[0].(map[string]interface{})
		content, _ := cand["content"].(map[string]interface{})
		parts, _ := content["parts"].([]interface{})
		if len(parts) > 0 {
			part := parts[0].(map[string]interface{})
			contentStr, _ = part["text"].(string)
		}
	}

	anthropicResp := map[string]interface{}{
		"id":    "msg_123",
		"type":  "message",
		"role":  "assistant",
		"model": model,
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": contentStr,
			},
		},
		"stop_reason": "end_turn",
		"usage": map[string]interface{}{
			"input_tokens":  0,
			"output_tokens": 0,
		},
	}

	return anthropicResp, nil
}
