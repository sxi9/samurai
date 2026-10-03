#!/usr/bin/env bash
# =====================================================================
#  SamurAI bootstrap — idempotent. Safe to re-run on any Brev instance.
#  Installs Ollama, pulls models (only if missing), sets up the app,
#  and launches it with a public share URL.
#
#  Models and app live under /home/ubuntu/workspace, which is the ONLY
#  path that survives a Brev **Stop** (it is wiped on **Delete**).
#  => Stop, don't Delete, between sessions and the 66GB downloads ONCE.
#
#  Usage on a fresh instance:
#    curl -fsSL <raw-url-of-this-file> | bash
#  or:
#    bash bootstrap.sh
# =====================================================================
set -euo pipefail

# ---------- config (edit REPO_URL after you push to GitHub) ----------
WORKSPACE="${WORKSPACE:-$HOME/workspace}"
export OLLAMA_MODELS="$WORKSPACE/ollama-models"   # persists across a Stop
APP_DIR="$WORKSPACE/samurai"
REPO_URL="${REPO_URL:-}"                           # e.g. https://github.com/you/samurai.git
SEC_MODEL="hf.co/manuelgutierrez/WhiteRabbitNeo-33B-v1.5-GGUF:Q4_K_M"
REP_MODEL="hf.co/mradermacher/Qwen2.5-72B-Instruct-abliterated-GGUF:Q4_K_M"

mkdir -p "$WORKSPACE" "$OLLAMA_MODELS"

# ---------- 1. Ollama ----------
if ! command -v ollama >/dev/null 2>&1; then
  echo "[*] Installing Ollama..."
  curl -fsSL https://ollama.com/install.sh | sh
fi

# Take control of the model path + ownership: stop the systemd service and
# run the server ourselves as this user, pointed at the persistent dir.
sudo systemctl stop ollama    2>/dev/null || true
sudo systemctl disable ollama 2>/dev/null || true

export OLLAMA_HOST=0.0.0.0:11434
if ! curl -sf http://localhost:11434/api/version >/dev/null 2>&1; then
  echo "[*] Starting Ollama server (models -> $OLLAMA_MODELS)..."
  nohup ollama serve > "$WORKSPACE/ollama.log" 2>&1 &
  until curl -sf http://localhost:11434/api/version >/dev/null 2>&1; do sleep 1; done
fi

# ---------- 2. models (pull only if missing) ----------
pull_if_missing() {
  local model="$1" base="${1%%:*}"
  if ollama list | awk '{print $1}' | grep -qx "$model" || ollama list | grep -q "$base"; then
    echo "[=] $model already present — skipping download"
  else
    echo "[*] Pulling $model (this is the big one) ..."
    ollama pull "$model"
  fi
}
pull_if_missing "$SEC_MODEL"
pull_if_missing "$REP_MODEL"

# ---------- 3. app code ----------
if [ -n "$REPO_URL" ]; then
  if [ -d "$APP_DIR/.git" ]; then
    echo "[*] Updating app from git..."; git -C "$APP_DIR" pull --ff-only || true
  else
    echo "[*] Cloning app..."; git clone "$REPO_URL" "$APP_DIR"
  fi
else
  echo "[!] REPO_URL not set — expecting app already at $APP_DIR (scp it there once)."
  mkdir -p "$APP_DIR"
fi

# ---------- 4. python env ----------
sudo apt-get update -qq 2>/dev/null || true
sudo apt-get install -y -qq python3-venv python3-pip 2>/dev/null || true
[ -d "$APP_DIR/venv" ] || python3 -m venv "$APP_DIR/venv"
# shellcheck disable=SC1091
source "$APP_DIR/venv/bin/activate"
pip install -q -r "$APP_DIR/requirements.txt"

# ---------- 5. launch (public share URL, survives SSH drops) ----------
cd "$APP_DIR"
pkill -f 'python3 app.py' 2>/dev/null || true
# ensure the app launches with a public gradio.live link
sed -i 's/share=False/share=True/' app.py 2>/dev/null || true
echo "[*] Launching SamurAI..."
nohup python3 app.py > "$WORKSPACE/samurai.log" 2>&1 &
sleep 12

echo ""
echo "============================================================"
grep -o 'https://[a-z0-9]*\.gradio\.live' "$WORKSPACE/samurai.log" \
  && echo "^ public URL (no SSH tunnel needed)" \
  || echo "Local only: http://localhost:7860  (check $WORKSPACE/samurai.log)"
echo "============================================================"
echo "[+] Bootstrap complete. Models in: $OLLAMA_MODELS"
echo "    Between sessions: STOP the instance (not Delete) to keep them."
