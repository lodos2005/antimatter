package auth

import (
	"antigravity-proxy-go/internal/config"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	GoogleTokenURL = "https://oauth2.googleapis.com/token"
	ClientID       = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
	ClientSecret   = "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"
)

type TokenData struct {
	AccessToken     string    `json:"access_token"`
	RefreshToken    string    `json:"refresh_token"`
	ExpiryTimestamp time.Time `json:"expiry_timestamp"`
}

type Account struct {
	ID             string    `json:"id"`
	Email          string    `json:"email"`
	Token          TokenData `json:"token"`
	ProjectID      string    `json:"project_id"`
	Tier           string    `json:"tier"`
	Disabled       bool      `json:"disabled"`
	DisabledAt     int64     `json:"disabled_at"`
	DisabledReason string    `json:"disabled_reason"`
}

type TokenManager struct {
	accounts []*Account
	mu       sync.RWMutex
	current  int
	client   *resty.Client
	strategy string // "round-robin" or "sequential"
}

func (tm *TokenManager) SetStrategy(strategy string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.strategy = strategy
}

func NewTokenManager(strategy string) *TokenManager {
	if strategy == "" {
		strategy = "round-robin"
	}
	return &TokenManager{
		accounts: []*Account{},
		client:   resty.New().SetTimeout(15 * time.Second),
		strategy: strategy,
	}
}

func (tm *TokenManager) AddAccount(email, refreshToken string, disabled bool, disabledAt int64, disabledReason string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	acc := &Account{
		Email: email,
		Token: TokenData{
			RefreshToken: refreshToken,
		},
		Disabled:       disabled,
		DisabledAt:     disabledAt,
		DisabledReason: disabledReason,
	}
	tm.accounts = append(tm.accounts, acc)
	return nil
}

func (tm *TokenManager) GetToken() (*Account, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if len(tm.accounts) == 0 {
		return nil, fmt.Errorf("no accounts available")
	}

	// Filter available accounts
	var available []*Account
	for _, a := range tm.accounts {
		if !a.Disabled {
			available = append(available, a)
		}
	}

	if len(available) == 0 {
		return nil, fmt.Errorf("no accounts available (all disabled)")
	}

	var acc *Account

	// Fix current pointer if it's out of bounds of tm.accounts (can happen if accounts were removed)
	if tm.current >= len(tm.accounts) {
		tm.current = 0
	}

	if tm.strategy == "sequential" {
		// In sequential mode, we find the first available starting from tm.current
		idx := tm.current
		for i := 0; i < len(tm.accounts); i++ {
			checkIdx := (idx + i) % len(tm.accounts)
			if !tm.accounts[checkIdx].Disabled {
				acc = tm.accounts[checkIdx]
				tm.current = checkIdx
				break
			}
		}
	} else {
		// Round-Robin: Rotate to next available
		for i := 0; i < len(tm.accounts); i++ {
			tm.current = (tm.current + 1) % len(tm.accounts)
			if !tm.accounts[tm.current].Disabled {
				acc = tm.accounts[tm.current]
				break
			}
		}
	}

	if acc == nil {
		return nil, fmt.Errorf("failed to find an available account")
	}

	// Ensure token is fresh
	if time.Now().After(acc.Token.ExpiryTimestamp.Add(-5 * time.Minute)) {
		if err := tm.RefreshToken(acc); err != nil {
			return nil, err
		}
	}

	return acc, nil
}

// OnFailure handles rotation logic when a request fails
func (tm *TokenManager) OnFailure() {
	if tm.strategy == "sequential" {
		tm.rotateCurrent()
	}
}

func (tm *TokenManager) rotateCurrent() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if len(tm.accounts) > 0 {
		tm.current = (tm.current + 1) % len(tm.accounts)
	}
}

func (tm *TokenManager) DisableAccount(email string, reason string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for _, acc := range tm.accounts {
		if acc.Email == email {
			acc.Disabled = true
			acc.DisabledAt = time.Now().Unix()
			acc.DisabledReason = reason
			
			// Persist to disk
			if err := config.SetAccountDisabled("settings.yaml", email, reason); err != nil {
				fmt.Printf("Failed to persist disabled state for %s: %v\n", email, err)
			}
			break
		}
	}
}

func (tm *TokenManager) GetAccounts() []*Account {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	accounts := make([]*Account, len(tm.accounts))
	copy(accounts, tm.accounts)
	return accounts
}

func (tm *TokenManager) RefreshToken(acc *Account) error {
	resp, err := tm.client.R().
		SetFormData(map[string]string{
			"client_id":     ClientID,
			"client_secret": ClientSecret,
			"refresh_token": acc.Token.RefreshToken,
			"grant_type":    "refresh_token",
		}).
		Post(GoogleTokenURL)

	if err != nil {
		return err
	}

	if !resp.IsSuccess() {
		body := resp.String()
		if strings.Contains(body, "invalid_grant") {
			acc.Disabled = true
			acc.DisabledAt = time.Now().Unix()
			reason := "invalid_grant: " + body
			acc.DisabledReason = reason
			
			// Persist to disk
			if err := config.SetAccountDisabled("settings.yaml", acc.Email, reason); err != nil {
				fmt.Printf("Failed to persist disabled state for %s: %v\n", acc.Email, err)
			}
		}
		return fmt.Errorf("failed to refresh token: %s", body)
	}

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.Unmarshal(resp.Body(), &data); err != nil {
		return err
	}

	acc.Token.AccessToken = data.AccessToken
	acc.Token.ExpiryTimestamp = time.Now().Add(time.Duration(data.ExpiresIn) * time.Second)

	return nil
}
