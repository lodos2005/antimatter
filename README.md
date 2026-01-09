# Antimatter 🚀

> **High-performance, fault-tolerant Go proxy for Google Cloud Code API with built-in Admin Panel & WebUI.**
>
> Antimatter acts as a universal gateway, converting **OpenAI**, **Anthropic**, and **Google** API requests into internal Google Cloud calls, unlocking the full potential of Gemini models (including Thinking/Reasoning) with multi-account rotation, enterprise-grade resilience, and comprehensive usage tracking.

## ✨ Why Antimatter?

- **⚡ Multi-Protocol Support:** Speak your language. Antimatter accepts requests in three major formats:
  - **OpenAI:** Drop-in replacement (`/v1/chat/completions`). Works with Cherry Studio, NextChat, LobeChat.
  - **Anthropic:** Compatible with Claude-style requests.
  - **Google:** Native support for `v1beta` endpoints (`/v1beta/models/...`).
- **🔗 LiteLLM Ready:** Perfect companion for **LiteLLM**. Use Antimatter as a reliable, rotating backend for your LLM gateway infrastructure.
- **🧠 Thinking & Reasoning:** Native support for **Gemini 2.5/3.0 Thinking** models. It automatically enables reasoning, adjusts output limits (64k), and streams the thought process via `reasoning_content` (DeepSeek R1 style).
- **🛡️ Iron-Clad Resilience:**
  - **Multi-Endpoint Fallback:** Automatically reroutes traffic between Google's **Prod** and **Daily/Sandbox** environments if `429` or `5xx` errors occur.
  - **Smart Rotation:** Round-robin load balancing across multiple accounts.
  - **Auto-Healing:** Automatically disables accounts with revoked tokens (`invalid_grant`).
- **📊 Admin Panel & WebUI:**
  - **Web Interface:** Built-in chat interface with model selection and real-time streaming
  - **Session Tracking:** Automatic cookie-based session management for conversation continuity
  - **Usage Analytics:** Comprehensive dashboard showing token usage, latency, and model statistics
  - **Security:** JWT-based authentication, CSRF protection, visual CAPTCHA, rate limiting, and IP banning
  - **Request Logging:** Full conversation history with prompt/response storage and session grouping

## 🛠️ Installation & Usage Guide

Follow these steps to get up and running.

### 1. Build the Binary

First, compile the project for your platform.

**macOS / Linux:**

```bash
cd antimatter
go build -o antimatter ./cmd/proxy
```

**Windows:**

```bash
cd antimatter
go build -o antimatter.exe ./cmd/proxy/main.go
```

### 2. Choose Your Mode

Antimatter supports two operational modes:

#### **Proxy Mode** (Default - Port 8045)

Standard API proxy for programmatic access.

```bash
./antimatter
```

Then use the login command in a separate terminal:

```bash
./antimatter login
```

#### **WebUI Mode** (Recommended - Ports 8045 + 8046)

Includes both proxy API **and** a web-based chat interface with admin panel.

```bash
./antimatter webui
```

- **Proxy API:** `http://localhost:8045`
- **Web Interface:** `http://localhost:8046`
- **Admin Panel:** `http://localhost:8046/admin.html`

The WebUI automatically handles account authentication via browser popup.

### 3. Access Admin Panel

When using WebUI mode, access the admin panel at:

```
http://localhost:8046/admin.html
```

**Default Credentials:**
- Password: `admin` (configurable in `settings.yaml`)

**Admin Features:**
- 📈 Real-time statistics dashboard
- 🔍 Recent activity logs (last 10 interactions)
- 💬 Session management (view all conversations grouped by session)
- 🔒 JWT-based authentication with auto-revocation
- 🖼️ Visual CAPTCHA protection after failed login attempts
- 🚫 Automatic IP banning and rate limiting

### 4. Check Status

Verify your accounts, subscription tiers (Free/Standard/Advanced), and current quota usage.

```bash
./antimatter status
```

_This will print a detailed table of all your added accounts and their remaining quotas._

---

## 🔌 Integration Examples

### 🟢 Using with LiteLLM

Antimatter is fully compatible with LiteLLM. Configure it as an OpenAI-compatible endpoint.

```yaml
model_list:
  - model_name: gemini-thinking
    litellm_params:
      model: openai/gemini-2.5-flash-thinking
      api_base: "http://127.0.0.1:8045/v1"
      api_key: "sk-antimatter" # Configured in settings.yaml
```

### 🟠 cURL (Thinking Model)

Trigger the "Thinking" process. Antimatter automatically handles the `thinkingConfig` injection.

```bash
curl -N http://127.0.0.1:8045/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-antimatter" \
  -d '{
    "model": "gemini-2.5-flash-thinking",
    "messages": [
      {"role": "user", "content": "How many r s in Strawberry? Think step by step."}
    ],
    "stream": true
  }'
```

### 🔵 Google Native Format (v1beta)

You can also use standard Google AI SDKs or curl with the `v1beta` endpoint.

```bash
curl "http://127.0.0.1:8045/v1beta/models/gemini-2.5-flash:generateContent" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"contents": [{"parts":[{"text": "Hello, world!"}]}]}'
```

### 🔴 Anthropic cURL

Call the Anthropic messages endpoint directly. Antimatter handles the conversion to Gemini.

```bash
curl http://127.0.0.1:8045/v1/messages \
     -X POST \
     -H "Content-Type: application/json" \
     -H "x-api-key: sk-antimatter" \
     -H "anthropic-version: 2023-06-01" \
     -d '{
       "model": "claude-sonnet-4-5-thinking",
       "max_tokens": 1024,
       "messages": [
         {"role": "user", "content": "Hello, Claude! (Actually Gemini)"}
       ]
     }'
```

## ⚙️ Configuration (`settings.yaml`)

The server will auto-generate a `settings.yaml` on first run if missing. You can customize it:

```yaml
server:
  port: 8045
  webui_port: 8046  # WebUI mode only

proxy:
  # Secure your proxy with API keys (Optional)
  api_keys:
    - "sk-antimatter"

  # Auth mode: "off" (default), "strict" (keys required), "all_except_health"
  auth_mode: "off"

  # Bind to 0.0.0.0 to allow LAN access
  allow_lan_access: false

  # Enable full request/response tracing to files (for debugging)
  debug: false

admin:
  enabled: true
  password: "admin"  # Change this!
  jwt_secret: "your-secret-key-here"  # Auto-generated if not set

models:
  fallback_model: "gemini-3-flash"

strategy:
  type: round-robin # Distributes requests evenly across accounts
```

## 🔐 Security Features

- **JWT Authentication:** Secure session management with automatic token revocation
- **CSRF Protection:** Cross-site request forgery prevention
- **Visual CAPTCHA:** Image-based verification after 5 failed login attempts
- **Rate Limiting:** Automatic IP banning after repeated failures
- **Session Tracking:** Cookie-based conversation continuity with 30-day expiration
- **CORS Configuration:** Properly configured for credential-based requests

## 📊 Database Schema

Antimatter automatically creates a SQLite database (`usage.db`) to track:
- Request logs (prompt, response, tokens, latency)
- Session grouping (conversations linked by session ID)
- Failed login attempts
- Banned IP addresses

## ⚠️ Disclaimer

This project is for educational and research purposes only. "Google", "Gemini", "Claude", and "OpenAI" are trademarks of their respective owners.
