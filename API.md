# Antimatter Proxy API Documentation

Antimatter is a lightweight, OpenAI-compatible proxy server for Google Gemini models. It provides unified access, load balancing, and usage tracking.

## Base URL
- **Local**: `http://127.0.0.1:8045`
- **LAN/Public**: `http://<YOUR_IP>:8045` (if configured with `host: 0.0.0.0`)

> Note: The Web UI typically runs on port `8046` or the same port depending on configuration, but API requests go to the main server port (default `8045`).

---

## Authentication

Authentication behavior depends on the `auth_mode` setting in `settings.yaml`.

- **Monitoring**: No auth required (default/public mode).
- **Strict**: Requires an API Key for all endpoints (except health).
- **All Except Health**: Requires an API Key for all endpoints except `/health` and `/v1/models`.

### Methods
You can provide the API key in one of two ways:

1. **Authorization Header** (Recommended):
   ```http
   Authorization: Bearer sk-your-api-key
   ```
2. **X-API-Key Header**:
   ```http
   x-api-key: sk-your-api-key
   ```

---

## User Endpoints (OpenAI Compatible)

### 1. Chat Completions
Generate text or chat responses using Gemini models via an OpenAI-compatible interface.

- **Endpoint**: `POST /v1/chat/completions`
- **Content-Type**: `application/json`

**Request Body:**
```json
{
  "model": "gemini-3-flash",
  "messages": [
    { "role": "system", "content": "You are a helpful assistant." },
    { "role": "user", "content": "Hello!" }
  ],
  "stream": true,
  "temperature": 0.7
}
```

**Response (Streamed):**
Server-Sent Events (SSE) stream, compatible with OpenAI clients.

**Response (Non-Streamed):**
```json
{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "created": 1709...,
  "model": "gemini-3-flash",
  "choices": [ ... ],
  "usage": { ... }
}
```

### 2. List Models
Retrieve available models from the upstream provider.

- **Endpoint**: `GET /v1/models`

**Response:**
```json
{
  "object": "list",
  "data": [
    { "id": "gemini-3-flash", "object": "model", "owned_by": "google" },
    { "id": "gemini-3-pro-high", "object": "model", "owned_by": "google" }
    ...
  ]
}
```

### 3. Health Check
Check if the proxy is running.

- **Endpoint**: `GET /health`

**Response:**
```json
{ "status": "ok" }
```

---

## Admin API (Private)

These endpoints allow management of the proxy server. They operate on a separate session-based authentication system (Admin Panel Login).

**Base Path**: `/api/admin`

### Authentication

#### Login
- **Endpoint**: `POST /api/admin/login`
- **Body**: `{ "password": "your-admin-password" }`
- **Response**: Sets `admin_session` cookie.

#### Logout
- **Endpoint**: `POST /api/admin/logout`

### Dashboard Data

#### Get Statistics
Returns aggregated usage stats (token counts, request counts).
- **Endpoint**: `GET /api/admin/stats`

#### Get Recent Logs
Returns a list of recent request logs.
- **Endpoint**: `GET /api/admin/logs?limit=50`

#### Get Sessions
Returns grouped session history.
- **Endpoint**: `GET /api/admin/sessions?page=1&limit=10`

#### Get Session Details
Returns full message history for a specific session ID.
- **Endpoint**: `GET /api/admin/session/:session_id`

### Configuration Management

#### Get Config settings
- **Endpoint**: `GET /api/admin/config`

#### Update Config settings
- **Endpoint**: `POST /api/admin/config`
- **Body**: JSON object matching the `Config` struct.

### API Key Management

#### List API Keys
- **Endpoint**: `GET /api/admin/keys`

#### Create API Key
- **Endpoint**: `POST /api/admin/keys`
- **Body**: `{ "name": "My Application" }`
- **Response**: `{ "key": "sk-...", "name": "..." }`

#### Delete API Key
- **Endpoint**: `DELETE /api/admin/keys/:key`
