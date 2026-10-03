# SamurAI — AI-Powered Web Penetration Testing Tool

An AI-powered web application security scanner that combines automated vulnerability detection with intelligent analysis from self-hosted large language models. No API keys, no cloud dependencies, no restrictions.

## Features

**Automated Scanning**
- Security header analysis
- Technology stack fingerprinting
- DNS enumeration and subdomain discovery
- Endpoint crawling with form/parameter extraction
- Sensitive file and path detection (`.env`, `.git`, backups, admin panels)

**Vulnerability Testing**
- Cross-Site Scripting (XSS) — reflected and DOM-based
- SQL Injection — error-based and boolean blind
- Server-Side Template Injection (SSTI)
- Local File Inclusion (LFI)
- CORS misconfiguration
- Open redirect

**AI-Powered Analysis (Dual Model)**
- **WhiteRabbitNeo 33B** — cybersecurity-specialized model for vulnerability analysis, exploit suggestions, and payload generation
- **Qwen 72B Abliterated** — uncensored 72B parameter model for detailed report writing and general security consultation

**Tooling**
- One-click bug bounty report generation (HackerOne/Bugcrowd ready)
- AI exploit suggestion engine
- Payload generator for 14+ vulnerability types
- Interactive security chat — ask anything, no filters

## Architecture

```
Target URL
    │
    ▼
┌─────────────────────────────┐
│  RECONNAISSANCE             │
│  Headers · Tech · DNS ·     │
│  Crawl · Path Discovery     │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  VULNERABILITY SCANNING     │
│  XSS · SQLi · SSTI · LFI · │
│  CORS · Open Redirect       │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  AI ANALYSIS                │
│  WhiteRabbitNeo → Exploits  │
│  Qwen 72B → Reports        │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  OUTPUT                     │
│  Pentest Report ·           │
│  Bug Bounty Submission ·    │
│  Exploit Guides             │
└─────────────────────────────┘
```

## Requirements

- NVIDIA GPU with 48GB+ VRAM (tested on H200 141GB)
- [Ollama](https://ollama.com) installed
- Python 3.10+

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/samurai-ai-pentest.git
cd samurai-ai-pentest

# Deploy (installs everything)
chmod +x deploy.sh
./deploy.sh
```

Or manually:

```bash
# Pull the models
ollama pull hf.co/manuelgutierrez/WhiteRabbitNeo-33B-v1.5-GGUF:Q4_K_M
ollama pull hf.co/mradermacher/Qwen2.5-72B-Instruct-abliterated-GGUF:Q4_K_M

# Install dependencies
pip install -r requirements.txt

# Run
python app.py
```

Open `http://localhost:7860` in your browser.

## Docker

```bash
# Build
docker build -t samurai-pentest .

# Run (requires Ollama running on host)
docker run -p 7860:7860 --network host samurai-pentest
```

## Usage

### Scanner Tab
1. Enter target URL
2. Select scan depth (Quick / Normal / Deep)
3. Click "Launch Scan"
4. View real-time scan log, AI-generated pentest report, and findings summary

### Bug Bounty Reporter Tab
1. Run a scan first
2. Enter the finding number
3. Generate a submission-ready bug bounty report or detailed exploit guide

### AI Chat Tab
Ask any security question — payload crafting, exploitation techniques, WAF bypasses, privilege escalation, reverse engineering. Powered by WhiteRabbitNeo with no content restrictions.

### Payload Generator Tab
Select a vulnerability type and optional context, get 10+ working payloads with WAF bypass variants.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| UI | Gradio |
| Security Model | WhiteRabbitNeo 33B |
| Report Model | Qwen 2.5 72B (Abliterated) |
| Inference | Ollama |
| Scanning | httpx, BeautifulSoup, dnspython |
| Hardware | NVIDIA H200 (141GB VRAM) |

## Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper authorization before scanning any target. The authors are not responsible for any misuse of this tool.

## License

MIT
