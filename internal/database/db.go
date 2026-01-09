package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB(dsn string) error {
	var err error
	DB, err = sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	if err := DB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	if err := createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	log.Printf("Database initialized at %s", dsn)
	return nil
}

func createTables() error {
	query := `
	CREATE TABLE IF NOT EXISTS request_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		model TEXT,
		user_id TEXT, -- Email or API key identifier
		prompt_tokens INTEGER,
		completion_tokens INTEGER,
		total_tokens INTEGER,
		status INTEGER,
		latency_ms INTEGER,
		prompt TEXT -- Added prompt column
	);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON request_logs(timestamp);
	
	CREATE TABLE IF NOT EXISTS banned_ips (
		ip TEXT PRIMARY KEY,
		reason TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS login_failures (
		ip TEXT PRIMARY KEY,
		count INTEGER DEFAULT 1,
		last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS revoked_tokens (
		token TEXT PRIMARY KEY,
		revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE,
		google_sub TEXT,
		role TEXT DEFAULT 'user',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS api_keys (
		key TEXT PRIMARY KEY,
		user_id INTEGER,
		name TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err := DB.Exec(query)

	// Migration: Attempt to add 'prompt' column if it doesn't exist
	// A simple brute-force ALTER is fine for now; if it fails (exists), we ignore.
	if err == nil {
		migration := "ALTER TABLE request_logs ADD COLUMN prompt TEXT;"
		DB.Exec(migration) // Ignore error if column exists

		migration2 := "ALTER TABLE request_logs ADD COLUMN response TEXT;"
		DB.Exec(migration2)

		migration3 := "ALTER TABLE request_logs ADD COLUMN session_id TEXT;"
		DB.Exec(migration3)
	}

	return err
}

type RequestLog struct {
	ID               int64     `json:"id"`
	Timestamp        time.Time `json:"timestamp"`
	Model            string    `json:"model"`
	UserID           string    `json:"user_id"`
	PromptTokens     int       `json:"prompt_tokens"`
	CompletionTokens int       `json:"completion_tokens"`
	TotalTokens      int       `json:"total_tokens"`
	Status           int       `json:"status"`
	LatencyMS        int64     `json:"latency_ms"`
	Prompt           string    `json:"prompt"`
	Response         string    `json:"response"`
	SessionID        string    `json:"session_id"`
}

func LogRequest(ctx context.Context, l *RequestLog) error {
	query := `
		INSERT INTO request_logs (timestamp, model, user_id, prompt_tokens, completion_tokens, total_tokens, status, latency_ms, prompt, response, session_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := DB.ExecContext(ctx, query, time.Now(), l.Model, l.UserID, l.PromptTokens, l.CompletionTokens, l.TotalTokens, l.Status, l.LatencyMS, l.Prompt, l.Response, l.SessionID)
	return err
}

func GetRecentLogs(limit int) ([]RequestLog, error) {
	query := `
		SELECT id, timestamp, model, user_id, prompt_tokens, completion_tokens, total_tokens, status, latency_ms, prompt, response, session_id
		FROM request_logs
		ORDER BY timestamp DESC
		LIMIT ?
	`
	rows, err := DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []RequestLog
	for rows.Next() {
		var l RequestLog
		// Handling possible NULL for prompt if rows were created before migration
		var prompt, response, sessionID sql.NullString

		if err := rows.Scan(&l.ID, &l.Timestamp, &l.Model, &l.UserID, &l.PromptTokens, &l.CompletionTokens, &l.TotalTokens, &l.Status, &l.LatencyMS, &prompt, &response, &sessionID); err != nil {
			return nil, err
		}
		if prompt.Valid {
			l.Prompt = prompt.String
		}
		if response.Valid {
			l.Response = response.String
		}
		if sessionID.Valid {
			l.SessionID = sessionID.String
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// Pagination & List
func GetSessions(page, limit int, modelFilter, ipFilter string) ([]RequestLog, int, error) {
	whereClause := "WHERE 1=1" // Start with a neutral condition
	args := []interface{}{}

	if modelFilter != "" {
		whereClause += " AND model = ?"
		args = append(args, modelFilter)
	}
	if ipFilter != "" {
		whereClause += " AND user_id = ?"
		args = append(args, ipFilter)
	}

	// Get Total Count of distinct sessions (including non-session requests grouped by ID)
	var total int
	countQuery := "SELECT COUNT(DISTINCT COALESCE(NULLIF(session_id, ''), 'unknown-' || CAST(id AS TEXT))) FROM request_logs " + whereClause
	err := DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get session IDs for this page only
	offset := (page - 1) * limit
	sessionIDQuery := fmt.Sprintf(`
		SELECT DISTINCT COALESCE(NULLIF(session_id, ''), 'unknown-' || CAST(id AS TEXT)) as sid
		FROM request_logs
		%s
		GROUP BY COALESCE(NULLIF(session_id, ''), 'unknown-' || CAST(id AS TEXT))
		ORDER BY MAX(timestamp) DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	sessionArgs := append(args, limit, offset)
	rows, err := DB.Query(sessionIDQuery, sessionArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	sessionIDs := []string{}
	for rows.Next() {
		var sid string
		rows.Scan(&sid)
		sessionIDs = append(sessionIDs, sid)
	}

	if len(sessionIDs) == 0 {
		return []RequestLog{}, total, nil
	}

	// Now get ALL logs for these sessions
	placeholders := make([]string, len(sessionIDs))
	queryArgs := []interface{}{}
	for i, sid := range sessionIDs {
		placeholders[i] = "?"
		queryArgs = append(queryArgs, sid)
	}

	query := fmt.Sprintf(`
		SELECT id, timestamp, model, user_id, prompt_tokens, completion_tokens, total_tokens, status, latency_ms, prompt, response,
		       COALESCE(NULLIF(session_id, ''), 'unknown-' || CAST(id AS TEXT)) as session_id
		FROM request_logs
		WHERE COALESCE(NULLIF(session_id, ''), 'unknown-' || CAST(id AS TEXT)) IN (%s)
		ORDER BY timestamp ASC
	`, strings.Join(placeholders, ","))

	allRows, err := DB.Query(query, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer allRows.Close()

	var logs []RequestLog
	for allRows.Next() {
		var l RequestLog
		var prompt, response, sessionID sql.NullString
		err := allRows.Scan(&l.ID, &l.Timestamp, &l.Model, &l.UserID, &l.PromptTokens, &l.CompletionTokens,
			&l.TotalTokens, &l.Status, &l.LatencyMS, &prompt, &response, &sessionID)
		if err != nil {
			return nil, 0, err
		}
		if prompt.Valid {
			l.Prompt = prompt.String
		}
		if response.Valid {
			l.Response = response.String
		}
		if sessionID.Valid {
			l.SessionID = sessionID.String
		}
		logs = append(logs, l)
	}
	return logs, total, nil
}

func GetSessionDetails(sessionID string) ([]RequestLog, error) {
	query := `
		SELECT id, timestamp, model, user_id, prompt_tokens, completion_tokens, total_tokens, status, latency_ms, prompt, response, session_id
		FROM request_logs
		WHERE session_id = ?
		ORDER BY timestamp ASC
	`
	rows, err := DB.Query(query, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []RequestLog
	for rows.Next() {
		var l RequestLog
		var prompt, response, sessionID sql.NullString
		if err := rows.Scan(&l.ID, &l.Timestamp, &l.Model, &l.UserID, &l.PromptTokens, &l.CompletionTokens, &l.TotalTokens, &l.Status, &l.LatencyMS, &prompt, &response, &sessionID); err != nil {
			return nil, err
		}
		if prompt.Valid {
			l.Prompt = prompt.String
		}
		if response.Valid {
			l.Response = response.String
		}
		if sessionID.Valid {
			l.SessionID = sessionID.String
		}
		logs = append(logs, l)
	}
	return logs, nil
}

type UsageStats struct {
	TotalRequests   int64 `json:"total_requests"`
	TotalTokens     int64 `json:"total_tokens"`
	TotalPrompt     int64 `json:"total_prompt"`
	TotalCompletion int64 `json:"total_completion"`
	RequestsLast24h int64 `json:"requests_last_24h"`
}

func GetUsageStats() (*UsageStats, error) {
	// Simple aggregate query
	query := `
		SELECT 
			COUNT(*) as total_requests,
			COALESCE(SUM(total_tokens), 0) as total_tokens,
			COALESCE(SUM(prompt_tokens), 0) as total_prompt,
			COALESCE(SUM(completion_tokens), 0) as total_completion
		FROM request_logs
	`
	stats := &UsageStats{}
	err := DB.QueryRow(query).Scan(&stats.TotalRequests, &stats.TotalTokens, &stats.TotalPrompt, &stats.TotalCompletion)
	if err != nil {
		return nil, err
	}

	query24h := `SELECT COUNT(*) FROM request_logs WHERE timestamp > datetime('now', '-1 day')`
	err = DB.QueryRow(query24h).Scan(&stats.RequestsLast24h)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// Rate Limiting & Banning

type BannedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

func IsBanned(ip string) (bool, string, error) {
	var reason string
	err := DB.QueryRow("SELECT reason FROM banned_ips WHERE ip = ?", ip).Scan(&reason)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, reason, nil
}

func BanIP(ip string, reason string) error {
	_, err := DB.Exec("INSERT OR REPLACE INTO banned_ips (ip, reason, created_at) VALUES (?, ?, ?)", ip, reason, time.Now())
	return err
}

func IncrementFailure(ip string) (int, error) {
	// Upsert failure count
	query := `
		INSERT INTO login_failures (ip, count, last_attempt) 
		VALUES (?, 1, ?)
		ON CONFLICT(ip) DO UPDATE SET 
			count = count + 1, 
			last_attempt = excluded.last_attempt
	`
	_, err := DB.Exec(query, ip, time.Now())
	if err != nil {
		return 0, err
	}

	return GetFailureCount(ip)
}

func ResetFailure(ip string) error {
	_, err := DB.Exec("DELETE FROM login_failures WHERE ip = ?", ip)
	return err
}

func GetFailureCount(ip string) (int, error) {
	var count int
	err := DB.QueryRow("SELECT count FROM login_failures WHERE ip = ?", ip).Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return count, nil
}

func RevokeToken(token string, expiresAt time.Time) error {
	_, err := DB.Exec("INSERT INTO revoked_tokens (token, expires_at) VALUES (?, ?)", token, expiresAt)
	return err
}

func IsTokenRevoked(token string) bool {
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM revoked_tokens WHERE token = ?", token).Scan(&count)
	return count > 0
}

func CleanRevokedTokens() {
	DB.Exec("DELETE FROM revoked_tokens WHERE expires_at < datetime('now')")
}

// User & API Key Management

type User struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type APIKey struct {
	Key       string    `json:"key"`
	UserID    int64     `json:"user_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// ValidateAPIKey checks if the key exists in the database
func ValidateAPIKey(key string) (bool, error) {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM api_keys WHERE key = ?", key).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CreateAPIKey adds a new API key
func CreateAPIKey(key string, userID int64, name string) error {
	_, err := DB.Exec("INSERT INTO api_keys (key, user_id, name) VALUES (?, ?, ?)", key, userID, name)
	return err
}

// GetUserByEmail finds a user by email
func GetUserByEmail(email string) (*User, error) {
	u := &User{}
	err := DB.QueryRow("SELECT id, email, role, created_at FROM users WHERE email = ?", email).Scan(&u.ID, &u.Email, &u.Role, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil // Not found
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// CreateUser creates a new user
func CreateUser(email, googleSub string) (int64, error) {
	res, err := DB.Exec("INSERT INTO users (email, google_sub) VALUES (?, ?)", email, googleSub)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetAPIKeys lists all API keys
func GetAPIKeys() ([]APIKey, error) {
	rows, err := DB.Query("SELECT key, user_id, name, created_at FROM api_keys ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var k APIKey
		var name sql.NullString
		var userID sql.NullInt64
		if err := rows.Scan(&k.Key, &userID, &name, &k.CreatedAt); err != nil {
			return nil, err
		}
		if name.Valid {
			k.Name = name.String
		}
		if userID.Valid {
			k.UserID = userID.Int64
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// DeleteAPIKey deletes a key
func DeleteAPIKey(key string) error {
	_, err := DB.Exec("DELETE FROM api_keys WHERE key = ?", key)
	return err
}

// GetSessionRequestCount returns the number of requests made by a specific session ID
func GetSessionRequestCount(sessionID string) (int, error) {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM request_logs WHERE session_id = ?", sessionID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetSessionTokenCount returns the total number of tokens used by a specific session ID
func GetSessionTokenCount(sessionID string) (int64, error) {
	var total int64
	// Use COALESCE to handle NULL summing to 0 if no rows or null values
	err := DB.QueryRow("SELECT COALESCE(SUM(total_tokens), 0) FROM request_logs WHERE session_id = ?", sessionID).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}
