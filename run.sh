#!/usr/bin/env bash
cd "$HOME/workspace/samurai"
source venv/bin/activate
export OLLAMA_MODELS="$HOME/workspace/ollama-models"
exec python3 -u app.py
