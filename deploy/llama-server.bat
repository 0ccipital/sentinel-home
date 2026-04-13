@echo off
REM ============================================================================
REM  SentinelHome — llama.cpp server for Qwen3.5-9B
REM
REM  Model:    Qwen3.5-9B (Q8_0 quant, ~9.5 GB — or Q6_K ~7.3 GB)
REM  Requires: GPU with ≥12 GB VRAM (16+ GB recommended for Q8_0 at 16k context)
REM  Purpose:  Micro-task inference for SentinelHome agent (triage, classify, evaluate)
REM
REM  This script launches llama-server directly. If you're using Open WebUI
REM  with Ollama, use the ollama-modelfile.txt instead.
REM ============================================================================

REM === EDIT THESE PATHS ===
SET LLAMA_SERVER=C:\llama.cpp\build\bin\Release\llama-server.exe
SET MODEL_PATH=C:\models\Qwen3.5-9B-Q8_0.gguf

REM === Server config ===
SET HOST=0.0.0.0
SET PORT=8081

REM === Model parameters tuned for SentinelHome ===
REM
REM  Context: 16384 — 9B dense model has plenty of VRAM headroom on 16GB.
REM  Larger context lets investigator model see richer data packets.
REM
REM  GPU layers: 99 = offload everything to GPU. Q8_0 at ~9.5GB fits
REM  easily in 16GB VRAM with 16k context.
REM
REM  Threads: Match your physical core count (not HT). Adjust for your CPU.
REM
REM  Parallel: 2 allows actor to queue a second request while the first
REM  is generating. Don't go higher — each slot reserves context memory.
REM
REM  Flash attention: Reduces VRAM usage for KV cache.
REM
REM  Continuous batching: Lets parallel requests share compute efficiently.

%LLAMA_SERVER% ^
  --model "%MODEL_PATH%" ^
  --host %HOST% ^
  --port %PORT% ^
  --ctx-size 16384 ^
  --n-gpu-layers 99 ^
  --threads 8 ^
  --parallel 2 ^
  --flash-attn ^
  --cont-batching ^
  --mlock ^
  --no-warmup ^
  --log-disable ^
  --chat-template-kwargs "{\"enable_thinking\":false}"

REM ============================================================================
REM  Notes:
REM
REM  Memory estimate (Q8_0 @ 16k ctx, 2 parallel slots):
REM    Model weights:  ~9.5 GB
REM    KV cache:       ~1.6 GB (2 slots x 16k ctx)
REM    Overhead:       ~0.5 GB
REM    Total:          ~11.6 GB / 16 GB available
REM
REM  If you hit OOM, reduce --ctx-size to 8192 or use Q6_K quant (~7.3 GB).
REM
REM  If using Ollama instead, create the model with:
REM    ollama create sentinel-qwen -f deploy/ollama-modelfile.txt
REM
REM  API endpoint: http://localhost:8081/v1/chat/completions
REM  (OpenAI-compatible, works directly with SentinelHome or Open WebUI)
REM ============================================================================
