package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
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
	offset := (page - 1) * limit
	whereClause := "WHERE 1=1"
	args := []interface{}{}

	if modelFilter != "" {
		whereClause += " AND model LIKE ?"
		args = append(args, "%"+modelFilter+"%")
	}
	if ipFilter != "" {
		whereClause += " AND user_id LIKE ?"
		args = append(args, "%"+ipFilter+"%")
	}

	// Get Total Count (including empty session_id as 'unknown')
	var total int
	countQuery := "SELECT COUNT(DISTINCT COALESCE(NULLIF(session_id, ''), 'unknown-' || CAST(id AS TEXT))) FROM request_logs " + whereClause
	err := DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get Sessions (Group by session_id, treating empty as individual sessions)
	query := fmt.Sprintf(`
		SELECT id, timestamp, model, user_id, prompt_tokens, completion_tokens, total_tokens, status, latency_ms, prompt, response, 
		       COALESCE(NULLIF(session_id, ''), 'unknown-' || CAST(id AS TEXT)) as session_id
		FROM request_logs
		%s
		GROUP BY COALESCE(NULLIF(session_id, ''), 'unknown-' || CAST(id AS TEXT))
		ORDER BY MAX(timestamp) DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	args = append(args, limit, offset)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []RequestLog
	for rows.Next() {
		var l RequestLog
		var prompt, response, sessionID sql.NullString
		if err := rows.Scan(&l.ID, &l.Timestamp, &l.Model, &l.UserID, &l.PromptTokens, &l.CompletionTokens, &l.TotalTokens, &l.Status, &l.LatencyMS, &prompt, &response, &sessionID); err != nil {
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
