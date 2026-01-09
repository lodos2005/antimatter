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
- **All Except Health**: Requires an API Key for all endpoints except `/health` and `/static/*`. (Enforced in `proxyadmin` mode).
- **Auto**: Uses `all_except_health` if exposed to usage (0.0.0.0), otherwise `off` for local only.

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
- **Auth**: Required (unless mode is `off`). WebUI sessions require `X-CSRF-Token` header.

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

#### Example Request

```bash
curl -X POST http://localhost:8045/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-your-api-key" \
  -d '{
    "model": "gemini-3-flash",
    "messages": [
        { "role": "system", "content": "You are a helpful assistant." },
        { "role": "user", "content": "Explain quantum physics in simple terms." }
    ],
    "stream": true,
    "temperature": 0.7
  }'
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
- **Auth**: Required in `strict` and `all_except_health` modes. (Accessible with Admin Session).

#### Example Request

```bash
curl http://localhost:8045/v1/models \
  -H "Authorization: Bearer sk-your-api-key"
```

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

#### Example Request

```bash
curl http://localhost:8045/health
```

---

## Admin API (Private)



### Authentication & Admin API Access

The Admin API supports two authentication methods:

1. **Bearer Token (Recommended for Scripts)**: Use your `admin.password` from `settings.yaml` as the Bearer token. **No CSRF token is required** when using this method.
2. **Browser Session**: Used by the Web UI. Relies on `admin_session` cookie (JWT) and requires `X-CSRF-Token` header for state-changing requests.

#### 1. Login (Browser Session Only)
(Only needed if you are NOT using the Bearer token method)

- **Endpoint**: `POST /api/admin/login`

**Request:**
```bash
curl -c cookies.txt -X POST http://localhost:8045/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{ "password": "your-admin-password" }'
```

**Response:**
Sets `admin_session` cookie (JWT).
```json
{ "status": "ok" }
```

#### 2. Logout (Browser Session Only)
- **Endpoint**: `POST /api/admin/logout`

---

### Dashboard Data

#### 3. Get Statistics
Returns aggregated usage stats (token counts, request counts).

- **Endpoint**: `GET /api/admin/stats`

**Request (Using Bearer Token):**
```bash
curl http://localhost:8045/api/admin/stats \
  -H "Authorization: Bearer your-admin-password"
```

#### 4. Get Recent Logs
Returns a list of recent request logs.

- **Endpoint**: `GET /api/admin/logs?limit=50`

**Request:**
```bash
curl "http://localhost:8045/api/admin/logs?limit=20" \
  -H "Authorization: Bearer your-admin-password"
```

#### 5. Get Sessions
Returns grouped session history.

- **Endpoint**: `GET /api/admin/sessions`

**Request:**
```bash
curl "http://localhost:8045/api/admin/sessions?page=1&limit=5" \
  -H "Authorization: Bearer your-admin-password"
```

#### 6. Get Session Details
Returns full message history for a specific session ID.

- **Endpoint**: `GET /api/admin/session/:session_id`

**Request:**
```bash
curl http://localhost:8045/api/admin/session/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer your-admin-password"
```

---

### Configuration Management

#### 7. Get Config Settings
- **Endpoint**: `GET /api/admin/config`

**Request:**
```bash
curl http://localhost:8045/api/admin/config \
  -H "Authorization: Bearer your-admin-password"
```

#### 8. Update Config Settings
- **Endpoint**: `POST /api/admin/config`

**Request:**
```bash
curl -X POST http://localhost:8045/api/admin/config \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-admin-password" \
  -d '{
    "server": { "port": 8045 },
    "proxy": { "debug": true },
    "session": { "webui_request_limit": 50, "webui_token_limit": 50000 }
  }'
```

---

### API Key Management

#### 9. List API Keys
- **Endpoint**: `GET /api/admin/keys`

**Request:**
```bash
curl http://localhost:8045/api/admin/keys \
  -H "Authorization: Bearer your-admin-password"
```

#### 10. Create API Key
- **Endpoint**: `POST /api/admin/keys`

**Request:**
```bash
curl -X POST http://localhost:8045/api/admin/keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-admin-password" \
  -d '{ "name": "MyApp Production" }'
```

**Response:**
```json
{
  "key": "sk-7f8a9d...",
  "name": "MyApp Production"
}
```

#### 11. Delete API Key
- **Endpoint**: `DELETE /api/admin/keys/:key`

**Request:**
```bash
curl -X DELETE http://localhost:8045/api/admin/keys/sk-7f8a9d... \
  -H "Authorization: Bearer your-admin-password"
```
