# Antimatter 🚀

> **High-performance, fault-tolerant Go proxy for Google Cloud Code API.**
>
> Antimatter acts as a universal gateway, converting **OpenAI**, **Anthropic**, and **Google** API requests into internal Google Cloud calls, unlocking the full potential of Gemini models (including Thinking/Reasoning) with multi-account rotation and enterprise-grade resilience.

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

## 🛠️ Installation & Usage Guide

Follow these steps to get up and running.

### 1. Build the Binary

First, compile the project for your platform.

**macOS / Linux:**

```bash
cd antigravity-proxy-go
go build -o antimatter ./cmd/proxy
```

**Windows:**

```bash
cd antigravity-proxy-go
GOOS=windows GOARCH=amd64 go build -o antimatter.exe ./cmd/proxy
```

### 2. Login (Add Accounts)

Antimatter needs Google accounts to function. Use the login command to authenticate. This will open your default browser to authorize the application.

```bash
./antimatter login
```

_Repeat this step for as many accounts as you want to add to the rotation pool._

### 3. Check Status

Verify your accounts, subscription tiers (Free/Standard/Advanced), and current quota usage.

```bash
./antimatter status
```

_This will print a detailed table of all your added accounts and their remaining quotas._

### 4. Start the Server

Start the proxy server. By default, it listens on port `8045`.

```bash
./antimatter
```

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

models:
  fallback_model: "gemini-3-flash"

strategy:
  type: round-robin # Distributes requests evenly across accounts
```

## ⚠️ Disclaimer

This project is for educational and research purposes only. "Google", "Gemini", "Claude", and "OpenAI" are trademarks of their respective owners.
