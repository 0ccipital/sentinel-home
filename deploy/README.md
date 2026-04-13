# SentinelHome Deployment Guide

## Architecture

```
 [Unraid Server]                     [Windows PC / GPU Host]
 ┌─────────────────────┐             ┌──────────────────────┐
 │  SentinelHome       │  HTTP API   │  llama.cpp server    │
 │  (Docker container) │◄───────────►│  OR Ollama           │
 │  port 8890          │             │  port 8081           │
 │                     │             │                      │
 │  ┌───────────────┐  │             │  ┌────────────────┐  │
 │  │ Collectors    │  │             │  │ Qwen3.5-27B    │  │
 │  │ Rule Engine   │  │             │  │ (or 9B)        │  │
 │  │ Agent Orch.   │  │             │  │ IQ4_XS quant     │  │
 │  │ Dashboard     │  │             │  └────────────────┘  │
 │  └───────────────┘  │             │                      │
 └─────────────────────┘             │  Open WebUI          │
                                     │  port 8084           │
                                     │  (chat, tools, RAG)  │
                                     └──────────────────────┘
```

## Quick Start

### 1. LLM Server (GPU Host)

**Option A: llama.cpp directly**

Edit paths in `llama-server.bat` (Windows) or `llama-server.sh` (Linux/macOS), then run it.
API available at `http://<PC_IP>:8081/v1/chat/completions`.

**Important: Disable thinking mode** for Qwen3.5 models. The launch scripts include
`--chat-template-kwargs '{"enable_thinking":false}'` which prevents the model from
using reasoning mode. Without this, the model puts answers in `reasoning_content`
instead of `content`, breaking micro-task extraction.

**Option B: Ollama**

```bash
ollama create sentinel-qwen -f deploy/ollama-modelfile.txt
ollama serve
```

**Option C: Open WebUI with Ollama backend**

If Open WebUI is already running with Ollama, just create the model via Ollama and
it appears in Open WebUI automatically.

### 2. Open WebUI Setup (Model Profiles + Tool + Knowledge)

Run the setup script from your Mac (or anywhere with network access to Open WebUI).
It makes API calls — it doesn't need to be run from the SentinelHome server.

```bash
# From the sentinel-home repo root:
uv run python scripts/setup_openwebui_models.py \
    --url http://<OPENWEBUI_IP>:8084 \
    --api-key sk-... \
    --base-model "sentinel"
```

**What it does:**

1. **Installs the SentinelHome Tool** (`deploy/openwebui-sentinel-tool.py`) into Open WebUI.
   This gives models 22 functions to read/write SentinelHome data during conversations,
   including HTML-embedded status views and UniFi write actions.

2. **Creates a Knowledge collection** for periodic network state RAG snapshots.
   SentinelHome pushes device/event/rule data here every 5 minutes.

3. **Creates three model profiles**, all backed by the same base model:

   | Profile | Purpose | Temperature | Context | Tools |
   |---------|---------|-------------|---------|-------|
   | `sentinel-analyst` | Actor/critic micro-tasks | 0.6 | 8K | None |
   | `sentinel-investigator` | Deep investigation | 0.6 | 16K | Tool + Web Search |
   | `sentinel-chat` | Dashboard chat | 1.0 | 16K | Tool |

**Finding your base model name:**

The `--base-model` is the model ID as Open WebUI sees it. To find it:
- Open WebUI UI: check the model selector dropdown
- Or the script will auto-detect if you omit `--base-model`
- Common values: `qwen3.5:9b`, `qwen3.5:24b`, or a custom name from `-a` flag in llama.cpp

**After setup — configure Tool Valves:**

The Tool needs to know where SentinelHome is running:

1. Open WebUI → Workspace → Tools → "SentinelHome" → gear icon (Valves)
2. Set `sentinel_url` to `http://<SENTINEL_IP>:8890/api/v1`
3. Set `sentinel_api_key` to your SentinelHome API key (from config.yaml or `SENTINEL_API_KEY` env)

### 3. (Optional) Install the Investigation Function

The investigation Function is an Open WebUI "pipe" that automatically enriches
investigation prompts with device context, recent alerts, and network state.

**Manual install** (Open WebUI doesn't have a create-function API yet):

1. Open WebUI → Workspace → Functions → (+) Add Function
2. Set type to "Pipe"
3. Paste contents of `deploy/openwebui-sentinel-function.py`
4. Save
5. Configure Valves (gear icon): set `sentinel_url` and `sentinel_api_key`

### 4. SentinelHome Container (Unraid)

```bash
# Create data directory
mkdir -p /mnt/user/sentinel

# Copy and edit config
cp config.yaml.example /mnt/user/sentinel/config.yaml
# Edit config.yaml — set agent URL, models, pihole, etc.

# Copy and edit env
cp .env.example /mnt/user/sentinel/.env
# Edit .env — set API keys

# Build and run
docker compose up -d --build
```

**Key config.yaml settings for the agent:**

```yaml
agent:
  enabled: true
  url: http://<OPENWEBUI_IP>:8084     # Open WebUI URL
  api_key: sk-...                       # Open WebUI API key
  model: sentinel-analyst               # Micro-task model
  chat_model: sentinel-chat             # Dashboard chat model
  investigator_model: sentinel-investigator  # Deep investigation model
```

### 5. Verify

- Dashboard: `http://<UNRAID_IP>:8890`
- API health: `curl http://<UNRAID_IP>:8890/api/v1/status`
- LLM health: `curl http://<PC_IP>:8081/health`

## Files in this directory

| File | Purpose |
|------|---------|
| `llama-server.bat` | Windows launch script for llama.cpp |
| `llama-server.sh` | Linux/macOS launch script for llama.cpp |
| `ollama-modelfile.txt` | Ollama model with tuned parameters |
| `openwebui-sentinel-tool.py` | Tool (22 functions) for Open WebUI models |
| `openwebui-sentinel-function.py` | Investigation pipe Function for Open WebUI |

## VRAM Budget

### Qwen3.5-27B IQ4_XS (recommended)

| Component | VRAM |
|-----------|------|
| Model weights (IQ4_XS) | ~13.5 GB |
| KV cache (8k ctx) | ~1.0 GB |
| CUDA overhead | ~0.5 GB |
| **Total** | **~15.0 GB / 16 GB** |

Tight fit on 16 GB. Context window limited to ~8K to stay within VRAM. Inference is slower but accuracy is noticeably better than 9B for classification and triage tasks.

### Qwen3.5-9B Q8_0 (lightweight)

| Component | VRAM |
|-----------|------|
| Model weights (Q8_0) | ~9.5 GB |
| KV cache (16k ctx, 2 slots) | ~1.6 GB |
| CUDA overhead | ~0.5 GB |
| **Total** | **~11.6 GB / 16 GB** |

Plenty of headroom. Faster inference, larger context window, good for most tasks.

## Thinking Mode (Qwen3.5)

Qwen3.5 models support a "thinking" mode where the model reasons internally before
answering. This is **not useful** for SentinelHome's micro-tasks (classify device,
triage event) which expect single-word or short JSON responses.

Thinking mode is disabled at three layers for defense in depth:

| Layer | Mechanism |
|-------|-----------|
| **llama-server** | `--chat-template-kwargs '{"enable_thinking":false}'` in launch script |
| **API request** | `chat_template_kwargs: {"enable_thinking": false}` sent in request body |
| **Prompt** | `/no_think` appended to system prompts for micro-tasks |

If you see `Using reasoning_content (content was empty)` in the logs, thinking mode
is still active somewhere in your stack. Check your launch script flags first.

## Open WebUI Configuration (v0.8.11+)

After installing Open WebUI, configure these features for optimal SentinelHome integration:

### Retrieval / RAG Settings (Admin → Settings → Documents)

- **Hybrid Search**: Enable for combined keyword + semantic retrieval. This significantly improves context retrieval from the SentinelHome Knowledge collection.
- **Reranking Model**: Set to `BAAI/bge-reranker-v2-m3`. Downloads automatically on first use. Reranks search results for better relevance.
- **Knowledge Search Scoping**: Ensures models only retrieve from their assigned Knowledge collections, not all documents.

### Model Capabilities

The setup script configures these automatically, but if editing manually:

- Enable **memory** capability on `sentinel-chat` so the model remembers facts across conversations (e.g., "the NAS is at 192.168.1.x")
- Enable **tools** on `sentinel-chat` and `sentinel-investigator` for API access during conversations
- Enable **web_search** on `sentinel-investigator` for threat intel lookups via SearXNG

### Tool HTML Embeds (v0.8.8+)

Three read tools return rich HTML cards alongside text context:
- `get_infrastructure_health()` — AP/switch/gateway status with CPU/memory/uptime indicators
- `get_network_topology()` — VLANs and SSIDs in a visual table
- `get_firewall_summary()` — Firewall zones and policy counts

These render inline in the chat as visual status displays. The text portion feeds the model's context so it can reason about the data.

---

## Where to Run Open WebUI

Open WebUI can run on the same server as SentinelHome or on the GPU host. It just
needs network access to both:
- The LLM backend (llama.cpp or Ollama)
- SentinelHome's API (for the Tool to call back)

Common setups:
- **Open WebUI on server, llama.cpp on GPU host** — most common
- **Open WebUI on GPU host, SentinelHome on server** — works if GPU host is always on
- **All on one machine** — simplest, if you have a GPU in your server
