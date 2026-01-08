package upstream

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
)

const (
	BaseURLProd  = "https://cloudcode-pa.googleapis.com/v1internal"
	BaseURLDaily = "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal"
)

var BaseURLs = []string{BaseURLProd, BaseURLDaily}

type Client struct {
	httpClient *resty.Client
}

func NewClient() *Client {
	return &Client{
		httpClient: resty.New().
			SetTimeout(120 * time.Second).
			SetHeader("User-Agent", "antigravity/1.11.9 windows/amd64"),
	}
}

// shouldRetry checks if we should try the next endpoint
func shouldRetry(status int) bool {
	return status == http.StatusTooManyRequests ||
		status == http.StatusRequestTimeout ||
		status == http.StatusNotFound ||
		(status >= 500 && status < 600)
}

func (c *Client) FetchProjectDetails(accessToken string) (string, string, error) {
	var lastErr error

	// Try endpoints in order
	for _, baseURL := range BaseURLs {
		resp, err := c.httpClient.R().
			SetAuthToken(accessToken).
			SetBody(map[string]interface{}{
				"metadata": map[string]string{
					"ideType": "ANTIGRAVITY",
				},
			}).
			Post(baseURL + ":loadCodeAssist")

		if err != nil {
			lastErr = err
			continue
		}

		if resp.IsSuccess() {
			var data struct {
				ProjectID   string `json:"cloudaicompanionProject"`
				CurrentTier *struct {
					ID string `json:"id"`
				} `json:"currentTier"`
				PaidTier    *struct {
					ID string `json:"id"`
				} `json:"paidTier"`
			}

			if err := json.Unmarshal(resp.Body(), &data); err != nil {
				// If JSON parse fails, it might be an invalid response, try next?
				// Usually 200 OK + invalid JSON means API change or severe issue.
				// We'll return error here to be safe.
				return "", "", err
			}

			if data.ProjectID == "" {
				data.ProjectID = generateMockProjectID()
			}

			tier := "Free"
			if data.PaidTier != nil && data.PaidTier.ID != "" {
				tier = data.PaidTier.ID
			} else if data.CurrentTier != nil && data.CurrentTier.ID != "" {
				tier = data.CurrentTier.ID
			}

			return data.ProjectID, tier, nil
		}

		status := resp.StatusCode()
		if shouldRetry(status) {
			lastErr = fmt.Errorf("upstream %s returned %d", baseURL, status)
			continue
		}

		// Non-retryable error (e.g. 401, 403)
		return "", "", fmt.Errorf("failed to fetch project: %s", resp.String())
	}

	return "", "", fmt.Errorf("all endpoints failed to fetch project details: %v", lastErr)
}

func generateMockProjectID() string {
	adjectives := []string{"useful", "bright", "swift", "calm", "bold"}
	nouns := []string{"fuze", "wave", "spark", "flow", "core"}
	
	adj := adjectives[rand.Intn(len(adjectives))]
	noun := nouns[rand.Intn(len(nouns))]
	
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 5)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	
	return fmt.Sprintf("%s-%s-%s", adj, noun, string(b))
}

type QuotaInfo struct {
	RemainingFraction float64 `json:"remainingFraction"`
	ResetTime         string  `json:"resetTime"`
}

type ModelInfo struct {
	QuotaInfo *QuotaInfo `json:"quotaInfo"`
}

type QuotaResponse struct {
	Models map[string]ModelInfo `json:"models"`
}

func (c *Client) FetchQuota(accessToken, projectID string) (map[string]ModelInfo, error) {
	var lastErr error

	for _, baseURL := range BaseURLs {
		resp, err := c.httpClient.R().
			SetAuthToken(accessToken).
			SetBody(map[string]interface{}{
				"project": projectID,
			}).
			Post(baseURL + ":fetchAvailableModels")

		if err != nil {
			lastErr = err
			continue
		}

		if resp.IsSuccess() {
			var data QuotaResponse
			if err := json.Unmarshal(resp.Body(), &data); err != nil {
				return nil, err
			}
			return data.Models, nil
		}

		status := resp.StatusCode()
		if shouldRetry(status) {
			lastErr = fmt.Errorf("upstream %s returned %d", baseURL, status)
			continue
		}

		return nil, fmt.Errorf("upstream error: %s", resp.String())
	}

	return nil, fmt.Errorf("all endpoints failed to fetch quota: %v", lastErr)
}

func (c *Client) GenerateContent(accessToken, projectID, model string, requestBody interface{}) ([]byte, error) {
	reqID := fmt.Sprintf("agent-%s", uuid.New().String())
	
	// Wrap into v1internal format
	wrappedBody := map[string]interface{}{
		"project":     projectID,
		"requestId":   reqID,
		"request":     requestBody,
		"model":       model,
		"userAgent":   "antigravity",
		"requestType": "agent",
	}

	var lastErr error

	for _, baseURL := range BaseURLs {
		resp, err := c.httpClient.R().
			SetAuthToken(accessToken).
			SetBody(wrappedBody).
			Post(baseURL + ":generateContent")

		if err != nil {
			lastErr = err
			continue
		}

		if resp.IsSuccess() {
			return resp.Body(), nil
		}

		status := resp.StatusCode()
		if shouldRetry(status) {
			lastErr = fmt.Errorf("upstream %s returned %d", baseURL, status)
			continue
		}

		return nil, fmt.Errorf("upstream error: %s", resp.String())
	}

	return nil, fmt.Errorf("all endpoints failed to generate content: %v", lastErr)
}

func (c *Client) StreamGenerateContent(accessToken, projectID, model string, requestBody interface{}) (io.ReadCloser, error) {
	reqID := fmt.Sprintf("agent-%s", uuid.New().String())
	
	wrappedBody := map[string]interface{}{
		"project":     projectID,
		"requestId":   reqID,
		"request":     requestBody,
		"model":       model,
		"userAgent":   "antigravity",
		"requestType": "agent",
	}

	var lastErr error

	for _, baseURL := range BaseURLs {
		resp, err := c.httpClient.R().
			SetDoNotParseResponse(true).
			SetAuthToken(accessToken).
			SetQueryParam("alt", "sse").
			SetBody(wrappedBody).
			Post(baseURL + ":streamGenerateContent")

		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode() == 200 {
			return resp.RawResponse.Body, nil
		}

		// Read error body
		bodyBytes, _ := io.ReadAll(resp.RawResponse.Body)
		resp.RawResponse.Body.Close()
		errorMsg := string(bodyBytes)

		status := resp.StatusCode()
		if shouldRetry(status) {
			lastErr = fmt.Errorf("upstream %s returned %d: %s", baseURL, status, errorMsg)
			continue
		}

		return nil, fmt.Errorf("upstream stream error status: %d, body: %s", status, errorMsg)
	}

	return nil, fmt.Errorf("all endpoints failed to stream content: %v", lastErr)
}