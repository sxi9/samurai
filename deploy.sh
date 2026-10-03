#!/bin/bash
set -e

echo "============================================"
echo "  SamurAI — AI Pentest Tool Deployment"
echo "============================================"
echo ""

# Install Ollama if not present
if ! command -v ollama &> /dev/null; then
    echo "[*] Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
fi

# Pull models
echo "[*] Pulling WhiteRabbitNeo 33B (security model)..."
ollama pull hf.co/manuelgutierrez/WhiteRabbitNeo-33B-v1.5-GGUF:Q4_K_M

echo "[*] Pulling Qwen 72B Abliterated (report model)..."
ollama pull hf.co/mradermacher/Qwen2.5-72B-Instruct-abliterated-GGUF:Q4_K_M

# Install Python dependencies
echo "[*] Setting up Python environment..."
python3 -m venv ~/samurai-env
source ~/samurai-env/bin/activate
pip install -q gradio httpx beautifulsoup4 ollama python-nmap dnspython

# Launch
echo ""
echo "============================================"
echo "  Starting SamurAI on port 7860"
echo "============================================"
echo ""
cd "$(dirname "$0")"
python3 app.py
