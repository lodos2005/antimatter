package auth

import (
	"antigravity-proxy-go/internal/config"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	AuthURL      = "https://accounts.google.com/o/oauth2/v2/auth"
	TokenURL     = "https://oauth2.googleapis.com/token"
	UserInfoURL  = "https://www.googleapis.com/oauth2/v2/userinfo"
	RedirectPath = "/oauth-callback"
)

type SavedAccount struct {
	Email        string `json:"email"`
	RefreshToken string `json:"refresh_token"`
}

// StartLoginServer starts the local listener and returns the login URL and a wait function
func StartLoginServer() (string, func() (*SavedAccount, error), error) {
	// 1. Start a listener on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("failed to start local server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d%s", port, RedirectPath)

	// 2. Create Auth URL
	scope := "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email"
	loginURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&access_type=offline&prompt=consent",
		AuthURL, ClientID, redirectURI, scope)

	// 3. Start server handler (asynchronously)
	mux := http.NewServeMux()
	server := &http.Server{
		Handler: mux,
	}
	
	type loginResult struct {
		account *SavedAccount
		err     error
	}
	done := make(chan loginResult, 1)

	mux.HandleFunc(RedirectPath, func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Authorization code not found", http.StatusBadRequest)
			done <- loginResult{err: fmt.Errorf("authorization code not found")}
			return
		}

		// Token exchange
		client := resty.New()
		resp, err := client.R(). 
			SetFormData(map[string]string{
				"client_id":     ClientID,
				"client_secret": ClientSecret,
				"code":          code,
				"grant_type":    "authorization_code",
				"redirect_uri":  redirectURI,
			}).
			Post(TokenURL)

		if err != nil {
			http.Error(w, "Token exchange failed", http.StatusInternalServerError)
			log.Printf("Token error: %v", err)
			done <- loginResult{err: fmt.Errorf("token exchange failed: %w", err)}
			return
		}

		var tokenData struct {
			RefreshToken string `json:"refresh_token"`
			AccessToken  string `json:"access_token"`
		}
		if err := json.Unmarshal(resp.Body(), &tokenData); err != nil {
			http.Error(w, "Failed to read token response", http.StatusInternalServerError)
			done <- loginResult{err: fmt.Errorf("failed to read token response: %w", err)}
			return
		}

		// Get user info (Email)
		respUser, err := client.R().
			SetAuthToken(tokenData.AccessToken).
			Get(UserInfoURL)
		
		var userData struct {
			Email string `json:"email"`
		}
		json.Unmarshal(respUser.Body(), &userData)

		if tokenData.RefreshToken == "" {
			log.Println("WARNING: Failed to get Refresh Token. Remove app permissions from your Google account and try again.")
			http.Error(w, "Failed to get Refresh Token. Please reset permissions and try again.", http.StatusBadRequest)
			done <- loginResult{err: fmt.Errorf("failed to get refresh token")}
			return
		}

		// Save account
		if err := saveAccountToFile(userData.Email, tokenData.RefreshToken); err != nil {
			http.Error(w, "Failed to save account", http.StatusInternalServerError)
			log.Printf("Save error: %v", err)
			done <- loginResult{err: fmt.Errorf("failed to save account: %w", err)}
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`
			<html>
			<body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
				<h1 style="color: green;">Login Successful! ✅</h1>
				<p>Your account has been saved to <b>settings.yaml</b>.</p>
				<p>You can close this window and return to the terminal.</p>
				<script>setTimeout(function(){window.close()}, 3000)</script>
			</body>
			</html>
		`))
		
		log.Printf("Success! Account added: %s", userData.Email)
		
		// Signal success
		acc := &SavedAccount{
			Email:        userData.Email,
			RefreshToken: tokenData.RefreshToken,
		}
		done <- loginResult{account: acc, err: nil}

		// Shutdown server gracefully
		go func() {
			time.Sleep(1 * time.Second)
			server.Shutdown(context.Background())
		}()
	})

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()

	// Return a blocking function that waits for the result
	waitFunc := func() (*SavedAccount, error) {
		select {
		case res := <-done:
			return res.account, res.err
		case <-time.After(5 * time.Minute):
			server.Shutdown(context.Background())
			return nil, fmt.Errorf("login timed out")
		}
	}

	return loginURL, waitFunc, nil
}

// Login starts the interactive OAuth flow (Legacy wrapper)
func Login() (*SavedAccount, error) {
	url, waitFunc, err := StartLoginServer()
	if err != nil {
		return nil, err
	}
	
	fmt.Printf("\nPlease log in from the page opened in your browser:\n%s\n\n", url)
	openBrowser(url)
	
	return waitFunc()
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Printf("Failed to open browser: %v. Please open the link manually.", err)
	}
}

func saveAccountToFile(email, refreshToken string) error {
	filename := "settings.yaml"
	return config.AddOrUpdateAccount(filename, email, refreshToken)
}
