# LLM Provider Mode (AI Model Provider)

[Türkçe Versiyonu İçin Aşağı Kaydırın](#llm-provider-modu-model-sağlayıcı)

---

## English 🇬🇧

**LLM Provider** mode enables Antimatter to function as a standard **OpenAI-Compatible API**. In this mode, Antimatter receives chat requests, processes them using the Google Gemini API in the background, and returns the response in the OpenAI format.

This allows you to use Gemini models with hundreds of applications that don't natively support Google Gemini but support OpenAI.

### Features

*   **OpenAI Compatibility:** Provides `/v1/chat/completions` and `/v1/models` endpoints.
*   **Account Rotation:** Use multiple Google accounts to bypass Rate Limits.
*   **Smart Fallback:** Automatically switches to a backup model or account if the primary one fails or hits a limit.
*   **Logging:** All requests and **Thinking Processes** are logged and visible via the Admin Panel.

### Installation & Connection

When you start Antimatter via `antimatter.exe webui`, the LLM Provider service automatically starts at `http://localhost:8045`.

#### General Settings

Use these settings in any OpenAI-compatible client:

*   **Base URL (Endpoint):** `http://localhost:8045/v1`
*   **API Key:**
    *   If `Auth Mode: Off`: You can write anything random (e.g., `sk-antimatter`).
    *   If `Auth Mode: Strict`: Use an `sk-mcp-...` key generated from the Admin Panel.

#### Application Examples

**1. Cursor / VS Code (AI Extensions)**
*   **URL:** `http://localhost:8045/v1`
*   **API Key:** `sk-dummy` (or your key)
*   **Model Name:** `gemini-2.0-flash-exp`

**2. SillyTavern / Text Generation WebUI**
*   **API Type:** OpenAI (Chat Completions)
*   **API URL:** `http://localhost:8045/v1`
*   **Connect**: Click connect to fetch models.

**3. Python / Node.js SDK**

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8045/v1",
    api_key="none"
)

response = client.chat.completions.create(
    model="gemini-2.0-flash-exp",
    messages=[{"role": "user", "content": "Hello!"}]
)
print(response.choices[0].message.content)
```

#### Global System Prompt

You can configure a **Global System Prompt** via `settings.yaml` or the Admin Panel. This instruction is silently injected (prepended) into **all** requests made in Provider mode.

Example:
> "You are a helpful assistant that always responds in JSON format."

When set, all connected apps (Cursor, scripts, etc.) will adhere to this rule implicitly.

---

## Türkçe 🇹🇷

# LLM Provider Modu (Model Sağlayıcı)

**LLM Provider** modu, Antimatter'ın standart bir **OpenAI-Compatible API** (OpenAI Uyumlu API) olarak çalışmasını sağlar. Bu modda Antimatter, kendisine gelen sohbet isteklerini karşılar, arka planda Google Gemini API'sini kullanarak işler ve cevabı OpenAI formatında geri döndürür.

Bu sayede, Google Gemini'yi desteklemeyen ancak OpenAI destekleyen yüzlerce uygulama ile Gemini modellerini kullanabilirsiniz.

### Özellikler

*   **OpenAI Uyumluluğu:** `/v1/chat/completions` ve `/v1/models` uç noktalarını sağlar.
*   **Hesap Havuzu (Account Rotation):** Birden fazla Google hesabı ekleyerek hız limitlerini (Rate Limits) aşmanızı sağlar.
*   **Akıllı Yedekleme (Fallback):** Bir model hata verirse veya limit dolarsa otomatik olarak yedek modele veya hesaba geçer.
*   **Loglama:** Tüm istekler ve düşünce süreçleri (Thinking Process) kaydedilir ve Admin Paneli'nden izlenebilir.

### Kurulum ve Bağlantı

Antimatter'ı `webui` modunda başlattığınızda (`antimatter.exe webui`), LLM Provider servisi otomatik olarak `http://localhost:8045` adresinde çalışmaya başlar.

#### Genel Ayarlar

OpenAI uyumlu herhangi bir istemcide (Client) şu ayarları kullanın:

*   **Base URL (Endpoint):** `http://localhost:8045/v1`
*   **API Key:**
    *   Eğer `Auth Mode: Off` ise: Rastgele bir şey yazabilirsiniz (örn: `sk-antimatter`).
    *   Eğer `Auth Mode: Strict` ise: Admin panelinden oluşturduğunuz `sk-mcp-...` şeklindeki anahtarı girin.

#### Uygulama Bazlı Kurulumlar

**1. Cursor / VS Code (AI Eklentileri)**
*   **URL:** `http://localhost:8045/v1`
*   **API Key:** `sk-bos-gec` (veya kendi keyiniz)
*   **Model Adı:** `gemini-2.0-flash-exp` (veya kullanmak istediğiniz model)

**2. SillyTavern / Text Generation WebUI**
*   **API Type:** OpenAI (Chat Completions)
*   **API URL:** `http://localhost:8045/v1`
*   **API Key:** `1234`
*   **Connect** butonuna bastığınızda modeller listelenecektir.

**3. Python / Node.js ile Kullanım**

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8045/v1",
    api_key="gerek-yok"
)

response = client.chat.completions.create(
    model="gemini-2.0-flash-exp",
    messages=[{"role": "user", "content": "Merhaba!"}]
)

print(response.choices[0].message.content)
```

#### Global System Prompt

`settings.yaml` veya Admin Paneli üzerinden **Global System Prompt** ayarlayabilirsiniz. Bu komut, PROVIDER modunda yapılan **tüm** isteklere (istemci ne gönderirse göndersin) gizlice eklenir.

Örneğin:
> "Sen her zaman Türkçe ve resmi bir dille yanıt veren bir asistansın."

Bunu ayarladığınızda, bağlanan tüm uygulamalar (Cursor, SillyTavern vb.) bu kurala uyacaktır.
