# MCP Server Mode (Toolbox Server)

[Türkçe Versiyonu İçin Aşağı Kaydırın](#mcp-server-modu-araç-sunucusu)

---

## English 🇬🇧

**Model Context Protocol (MCP)** is an open standard that enables AI models (like Claude) to securely interact with the outside world, read data, and take actions.

When running in **MCP Server** mode, Antimatter acts not as a chatbot you talk to, but as a **toolbox** that another AI can use.

### Features

Antimatter MCP Server currently exposes the following tools:

1.  **`list_api_keys`**: Lists all registered API keys.
2.  **`create_api_key`**: Creates a new API key. (Params: `name`, `expires_in` e.g., "24h")
3.  **`get_recent_logs`**: Fetches the recent request logs passing through Antimatter. (Params: `limit` e.g., 10)

With these tools, for example, you can tell the AI in Claude Desktop: *"Check if there were any failed requests in Antimatter in the last 30 minutes"* or *"Create a new key for John valid for 7 days"*, and the AI will perform these actions for you automatically.

### Installation & Configuration

MCP Servers usually run over `stdio` (standard input/output). This means the server is started as a terminal command, and the Client interacts by spawning this command.

#### 1. Preparation

Enabling `mcp` mode in `settings.yaml` is **optional** but recommended for proper status display in the WebUI:

```yaml
mcp:
  mode: "server"
```

*Note: The MCP server DOES NOT start with `antimatter.exe webui`. The WebUI is for management only. The MCP server runs via a separate command (`antimatter.exe mcp`).*

#### 2. Connecting with Claude Desktop

Open the configuration file for Claude Desktop (`claude_desktop_config.json`). It is typically located at `%APPDATA%\Claude\claude_desktop_config.json` on Windows.

Modify the file as follows:

```json
{
  "mcpServers": {
    "antimatter": {
      "command": "C:\\PATH\\TO\\YOUR\\antimatter.exe",
      "args": [
        "mcp"
      ]
    }
  }
}
```

**Important:** Ensure you provide the **absolute path** to `antimatter.exe` in the `command` field.

#### 3. Usage

1.  Fully close and restart Claude Desktop.
2.  Click the "plug" icon (MCP menu) in the top right; you should see "antimatter" with a green indicator.
3.  You can now prompt Claude with requests like:
    *   "Check Antimatter logs."
    *   "Create a new API key for me."
    *   "List current API keys."

---

## Türkçe 🇹🇷

# MCP Server Modu (Araç Sunucusu)

**Model Context Protocol (MCP)**, yapay zeka modellerinin (Claude gibi) dış dünya ile etkileşime geçmesini, veri okumasını ve aksiyon almasını sağlayan açık bir standarttır.

Antimatter, **MCP Server** modunda çalıştığında, kendisiyle sohbet edilen bir yapay zeka olmak yerine, **başka bir yapay zekanın kullanabileceği bir alet çantası (toolbox)** görevi görür.

### Özellikler

Antimatter MCP Sunucusu şu anda aşağıdaki araçları (tools) sunmaktadır:

1.  **`list_api_keys`**: Kayıtlı tüm API anahtarlarını listeler.
2.  **`create_api_key`**: Yeni bir API anahtarı oluşturur. (Parametreler: `name`, `expires_in` örn: "24h")
3.  **`get_recent_logs`**: Antimatter üzerinden geçen son isteklerin loglarını getirir. (Parametreler: `limit` örn: 10)

Bu araçlar sayesinde, örneğin Claude Desktop uygulamasındaki yapay zekaya *"Antimatter'da son yarım saatte hata veren istek var mı?"* veya *"Ahmet için 7 gün geçerli yeni bir anahtar oluştur"* dediğinizde, yapay zeka bu işlemleri sizin yerinize otomatik olarak yapabilir.

### Kurulum ve Yapılandırma

MCP Sunucusu genellikle `stdio` (standart girdi/çıktı) üzerinden çalışır. Bu, sunucunun bir terminal komutu olarak başlatıldığı ve istemcinin (Client) bu komutu çalıştırarak iletişim kurduğu anlamına gelir.

#### 1. Hazırlık

Antimatter'ın `settings.yaml` dosyasında `mcp` modunu açmak **opsiyoneldir** ancak "webui" tarafında doğru bilgilendirme görmek için yapabilirsiniz:

```yaml
mcp:
  mode: "server"
```

*Not: MCP sunucusu `antimatter.exe webui` komutuyla BAŞLAMAZ. Web arayüzü sadece yönetim içindir. MCP sunucusu ayrı bir komutla (`antimatter.exe mcp`) çalıştırılır.*

#### 2. Claude Desktop ile Bağlantı

Claude Desktop uygulamasının yapılandırma dosyasını (`claude_desktop_config.json`) açın. Bu dosya genellikle şu konumdadır: `C:\Users\KULLANICI_ADINIZ\AppData\Roaming\Claude\claude_desktop_config.json`.

Dosyayı aşağıdaki gibi düzenleyin:

```json
{
  "mcpServers": {
    "antimatter": {
      "command": "C:\\KULLANICI\\YOLUNUZ\\antimatter.exe",
      "args": [
        "mcp"
      ]
    }
  }
}
```

**Önemli:** `command` kısmına `antimatter.exe` dosyasının **tam yolunu** (absolute path) yazdığınızdan emin olun.

#### 3. Kullanım

1.  Claude Desktop uygulamasını tamamen kapatıp yeniden başlatın.
2.  Sağ üstteki "fiş" ikonuna (MCP menüsü) tıkladığınızda "antimatter"ın yeşil (bağlı) olduğunu görmelisiniz.
3.  Artık Claude'a şu komutları verebilirsiniz:
    *   "Antimatter loglarını kontrol et."
    *   "Bana yeni bir API anahtarı oluştur."
    *   "Mevcut API anahtarlarını listele."
