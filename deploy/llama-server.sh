#!/usr/bin/env bash
# ============================================================================
#  SentinelHome — llama.cpp server for Qwen3.5-9B
#
#  Model:    Qwen3.5-9B (Q8_0 quant, ~9.5 GB — or Q6_K ~7.3 GB)
#  Requires: GPU with ≥12 GB VRAM (24 GB recommended for Q8_0 with headroom)
#  Purpose:  Micro-task inference for SentinelHome agent
# ============================================================================

# === EDIT THESE ===
LLAMA_SERVER="${LLAMA_SERVER:-llama-server}"
MODEL_PATH="${MODEL_PATH:-$HOME/models/Qwen3.5-9B-Q8_0.gguf}"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8081}"
THREADS="${THREADS:-8}"

exec "$LLAMA_SERVER" \
  --model "$MODEL_PATH" \
  --host "$HOST" \
  --port "$PORT" \
  --ctx-size 16384 \
  --n-gpu-layers 99 \
  --threads "$THREADS" \
  --parallel 2 \
  --flash-attn \
  --cont-batching \
  --mlock \
  --no-warmup \
  --log-disable \
  --chat-template-kwargs '{"enable_thinking":false}'
