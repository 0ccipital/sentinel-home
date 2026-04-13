#!/usr/bin/env python3
"""Create or update Open WebUI model profiles, tools, and knowledge for SentinelHome.

Three distinct profiles, all backed by the same base model (Qwen3.5-9B dense),
with different system prompts, temperatures, and tool configurations:

  sentinel-analyst   — Actor/critic micro-tasks.  Temp 0.6 (structured),
                       short tokens, constrained output.  No tools.
  sentinel-investigator — Deep investigation with web search.  Temp 0.6
                          (structured JSON), SearXNG enabled, SentinelHome tool.
  sentinel-chat      — Dashboard chat.  Temp 1.0 (general/creative),
                       conversational, long output.  SentinelHome tool.

Also installs:
  - SentinelHome Tool    — API access for network investigation and management
  - Knowledge collection — for periodic network state RAG snapshots

Qwen3.5-9B recommended temperatures:
  - 0.6 for structured/coding tasks (analyst, investigator)
  - 1.0 for general conversation (chat)

Usage:
    # Interactive — prompts for URL/key if not set
    python scripts/setup_openwebui_models.py

    # Non-interactive
    python scripts/setup_openwebui_models.py \\
        --url http://YOUR_HOST_IP:8084 \\
        --api-key sk-... \\
        --base-model "qwen3.5:9b"

    # Custom tool file path
    python scripts/setup_openwebui_models.py \\
        --tool-path /path/to/openwebui-sentinel-tool.py

    # From env
    OPENWEBUI_URL=http://YOUR_HOST_IP:8084 \\
    OPENWEBUI_API_KEY=sk-... \\
    python scripts/setup_openwebui_models.py
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

import httpx

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_ID = "sentinel-home"
TOOL_NAME = "SentinelHome"
KNOWLEDGE_NAME = "SentinelHome Network State"
KNOWLEDGE_DESCRIPTION = "Periodically updated network state for RAG context"

# Default tool file location relative to this script
_SCRIPT_DIR = Path(__file__).resolve().parent
_DEFAULT_TOOL_PATH = _SCRIPT_DIR.parent / "deploy" / "openwebui-sentinel-tool.py"

# ---------------------------------------------------------------------------
# Model definitions
# ---------------------------------------------------------------------------

MODELS = [
    {
        "id": "sentinel-analyst",
        "name": "Sentinel Analyst",
        "meta": {
            "description": (
                "SentinelHome actor/critic — constrained micro-tasks. "
                "Triage events, classify devices, evaluate rules. "
                "Temp 0.6, short output, no tools."
            ),
            "profile_image_url": "/static/favicon.png",
            "capabilities": {
                "web_search": False,
                "code_interpreter": False,
                "image_generation": False,
                "file_context": False,
                "vision": False,
                "file_upload": False,
                "citations": False,
                "status_updates": False,
                "builtin_tools": False,
            },
            "defaultFeatureIds": [],
            "builtinTools": {
                "time": False,
                "memory": False,
                "chats": False,
                "notes": False,
                "knowledge": False,
                "channels": False,
                "web_search": False,
                "image_generation": False,
                "code_interpreter": False,
            },
            "hidden": False,
            "tags": [{"name": "sentinel"}, {"name": "analyst"}],
        },
        "params": {
            "system": (
                "You are a home network security analyst for SentinelHome. "
                "You answer focused, constrained questions about network events, "
                "alerts, devices, and detection rules.\n\n"
                "RULES:\n"
                "- Answer with ONLY the requested format (a single choice, a number, or one word).\n"
                "- When asked to explain, give ONE sentence — never more.\n"
                "- Never add preamble, disclaimers, or markdown formatting.\n"
                "- If you're unsure, pick the most conservative option.\n"
                "- You will be given specific instructions per task. Follow them exactly."
            ),
            "temperature": 0.6,
            "top_p": 0.9,
            "top_k": 40,
            "max_tokens": 200,
            "repeat_penalty": 1.1,
            "num_ctx": 8192,
            # Disable Qwen3.5 thinking mode — micro-tasks need direct answers
            "enable_thinking": False,
        },
    },
    {
        "id": "sentinel-investigator",
        "name": "Sentinel Investigator",
        "meta": {
            "description": (
                "SentinelHome deep investigation — analyzes triggered rules with "
                "full network context. Can use web search (SearXNG) to look up "
                "IP reputation, CVEs, and threat intel. Returns structured JSON."
            ),
            "profile_image_url": "/static/favicon.png",
            "capabilities": {
                "web_search": True,
                "code_interpreter": False,
                "image_generation": False,
                "file_context": False,
                "vision": False,
                "file_upload": False,
                "citations": False,
                "status_updates": False,
                "builtin_tools": True,
            },
            "defaultFeatureIds": ["web_search"],
            "builtinTools": {
                "time": False,
                "memory": False,
                "chats": False,
                "notes": False,
                "knowledge": False,
                "channels": False,
                "web_search": True,
                "image_generation": False,
                "code_interpreter": False,
            },
            "toolIds": [TOOL_ID],
            "hidden": False,
            "tags": [{"name": "sentinel"}, {"name": "investigator"}],
        },
        "params": {
            "system": (
                "You are a network security analyst reviewing telemetry from a home network.\n"
                "You will receive a JSON context packet describing a triggered detection.\n\n"
                "You have access to web search — use it when it would meaningfully improve your analysis:\n"
                "- Look up unfamiliar external IPs (reputation, geolocation, ASN, known threat actor)\n"
                "- Search for CVEs related to targeted ports or protocols\n"
                "- Fetch threat intel pages for suspicious domains\n"
                "Keep searches focused — one or two lookups per finding at most.\n"
                "Do not search for obviously benign IPs (RFC1918, localhost, Cloudflare/Google DNS).\n\n"
                "After any research, respond ONLY with valid JSON matching this schema:\n"
                "{\n"
                '  "severity": "low|medium|high|critical",\n'
                '  "confidence": "low|medium|high",\n'
                '  "summary": "one sentence plain English finding",\n'
                '  "reasoning": "2-4 sentences explaining your assessment",\n'
                '  "likely_cause": "most probable explanation",\n'
                '  "recommended_action": "specific, actionable next step for the owner",\n'
                '  "needs_followup": true|false,\n'
                '  "followup_question": "if needs_followup, what to ask in second pass",\n'
                '  "mitre_reference": "ATT&CK technique if applicable, else null"\n'
                "}\n\n"
                "Be conservative. If uncertain, say so. Never invent IPs or device names not in the context.\n"
                "CRITICAL: Your entire response must be a single valid JSON object."
            ),
            "temperature": 0.6,
            "top_p": 0.9,
            "max_tokens": 2048,
            "num_ctx": 16384,
            "format": "json",
        },
    },
    {
        "id": "sentinel-chat",
        "name": "Sentinel Chat",
        "meta": {
            "description": (
                "SentinelHome dashboard chat — conversational assistant for "
                "home network questions. Natural tone, explains clearly, "
                "references specific devices and IPs."
            ),
            "profile_image_url": "/static/favicon.png",
            "capabilities": {
                "web_search": False,
                "code_interpreter": False,
                "image_generation": False,
                "file_context": False,
                "vision": False,
                "file_upload": False,
                "citations": False,
                "status_updates": False,
                "builtin_tools": False,
            },
            "defaultFeatureIds": [],
            "builtinTools": {
                "time": False,
                "memory": False,
                "chats": False,
                "notes": False,
                "knowledge": False,
                "channels": False,
                "web_search": False,
                "image_generation": False,
                "code_interpreter": False,
            },
            "toolIds": [TOOL_ID],
            "hidden": False,
            "tags": [{"name": "sentinel"}, {"name": "chat"}],
        },
        "params": {
            "system": (
                "You are a knowledgeable and friendly home network security assistant "
                "for SentinelHome. You help the user understand their network, "
                "investigate alerts, and make security decisions.\n\n"
                "STYLE:\n"
                "- Be conversational and clear — this is a chat, not a report.\n"
                "- Reference specific device names, IPs, and MACs when relevant.\n"
                "- Explain technical concepts simply when the user might not know them.\n"
                "- Offer actionable suggestions and follow-up questions.\n"
                "- Use short paragraphs. Bullet points are fine for lists.\n"
                "- If you don't have enough data, say so and suggest what to check.\n"
                "- Never fabricate device names, IPs, or events not in the context.\n\n"
                "You will receive current network state (devices, events, alerts) as context "
                "with each message. The context is refreshed each turn so you always see "
                "the latest data."
            ),
            "temperature": 1.0,
            "top_p": 0.95,
            "max_tokens": 1024,
            "num_ctx": 16384,
            "repeat_penalty": 1.05,
        },
    },
]


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def _check_response(resp: httpx.Response, context: str) -> bool:
    """Check HTTP response and print diagnostics on failure. Returns True if OK."""
    if resp.status_code == 401:
        print(f"  ERROR: 401 Unauthorized — {context}")
        print("  Your API key is invalid or missing. Generate one in Open WebUI:")
        print("    Settings -> Account -> API Keys -> Create new key")
        return False
    if resp.status_code >= 400:
        print(f"  ERROR: HTTP {resp.status_code} — {context}")
        try:
            print(f"    Response: {resp.json()}")
        except Exception:
            body = resp.text[:300]
            if body.startswith("<!") or body.startswith("<html"):
                print("    Response: HTML page (auth redirect or wrong URL?)")
            else:
                print(f"    Response: {body}")
        return False
    return True


def get_existing_models(client: httpx.Client, base_url: str, headers: dict) -> dict[str, dict]:
    """Fetch all existing models, return {id: model_data}."""
    # Open WebUI uses /api/v1/models (no trailing slash) for the workspace models list
    for path in ["/api/v1/models", "/api/v1/models/"]:
        try:
            resp = client.get(f"{base_url}{path}", headers=headers, timeout=15)
            if resp.status_code != 200:
                print(f"  Warning: {path} returned HTTP {resp.status_code}")
                continue
            text = resp.text.strip()
            if not text or text.startswith("<!") or text.startswith("<html"):
                print(f"  Warning: {path} returned HTML (auth redirect?), trying next...")
                continue
            data = resp.json()
            # API returns either a list or {"data": [...]}
            models = data if isinstance(data, list) else data.get("data", [])
            result = {m["id"]: m for m in models if "id" in m}
            print(f"  Found {len(result)} existing model(s) via {path}")
            return result
        except Exception as exc:
            print(f"  Warning: {path} failed: {exc}")
            continue

    print("  Warning: Could not list existing models — will attempt create for all")
    return {}


def create_model(
    client: httpx.Client,
    base_url: str,
    headers: dict,
    model_def: dict,
    base_model_id: str,
) -> bool:
    """Create a new model profile."""
    payload = {
        "id": model_def["id"],
        "name": model_def["name"],
        "base_model_id": base_model_id,
        "is_active": True,
        "params": model_def["params"],
        "meta": model_def["meta"],
    }

    resp = client.post(
        f"{base_url}/api/v1/models/create",
        json=payload,
        headers=headers,
        timeout=15,
    )
    if resp.status_code == 200:
        print(f"  ✓ Created '{model_def['id']}'")
        return True
    else:
        print(f"  ✗ Failed to create '{model_def['id']}': HTTP {resp.status_code}")
        try:
            print(f"    {resp.json()}")
        except Exception:
            print(f"    {resp.text[:200]}")
        return False


def update_model(
    client: httpx.Client,
    base_url: str,
    headers: dict,
    model_def: dict,
    base_model_id: str,
) -> bool:
    """Update an existing model profile (full replace)."""
    payload = {
        "id": model_def["id"],
        "name": model_def["name"],
        "base_model_id": base_model_id,
        "is_active": True,
        "params": model_def["params"],
        "meta": model_def["meta"],
    }

    resp = client.post(
        f"{base_url}/api/v1/models/model/update",
        json=payload,
        headers=headers,
        timeout=15,
    )
    if resp.status_code == 200:
        print(f"  ✓ Updated '{model_def['id']}'")
        return True
    else:
        print(f"  ✗ Failed to update '{model_def['id']}': HTTP {resp.status_code}")
        try:
            print(f"    {resp.json()}")
        except Exception:
            print(f"    {resp.text[:200]}")
        return False


def install_tool(
    client: httpx.Client,
    base_url: str,
    headers: dict,
    tool_content: str,
) -> bool:
    """Install or update the SentinelHome tool. Returns True on success."""
    # Check if tool already exists
    try:
        resp = client.get(f"{base_url}/api/v1/tools/", headers=headers, timeout=15)
        if not _check_response(resp, "listing tools"):
            return False
        existing_tools = resp.json()
        if not isinstance(existing_tools, list):
            existing_tools = existing_tools.get("data", [])
        tool_exists = any(t.get("id") == TOOL_ID for t in existing_tools)
    except Exception as exc:
        print(f"  Warning: could not list tools: {exc}")
        tool_exists = False

    payload = {
        "id": TOOL_ID,
        "name": TOOL_NAME,
        "content": tool_content,
    }

    if tool_exists:
        resp = client.post(
            f"{base_url}/api/v1/tools/id/update",
            json=payload,
            headers=headers,
            timeout=15,
        )
        if _check_response(resp, f"updating tool '{TOOL_ID}'"):
            print(f"  Updated tool '{TOOL_ID}'")
            return True
        return False
    else:
        resp = client.post(
            f"{base_url}/api/v1/tools/create",
            json=payload,
            headers=headers,
            timeout=15,
        )
        if _check_response(resp, f"creating tool '{TOOL_ID}'"):
            print(f"  Created tool '{TOOL_ID}'")
            return True
        return False


def create_knowledge(
    client: httpx.Client,
    base_url: str,
    headers: dict,
) -> str | None:
    """Create a Knowledge collection for network state snapshots.

    Returns the knowledge ID on success, or the existing ID if already present.
    Returns None on failure.
    """
    # Check for existing collection with same name
    try:
        resp = client.get(f"{base_url}/api/v1/knowledge/", headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            items = data if isinstance(data, list) else data.get("data", [])
            for item in items:
                if item.get("name") == KNOWLEDGE_NAME:
                    kid = item.get("id", "?")
                    print(f"  Knowledge collection already exists (id={kid})")
                    return kid
    except Exception as exc:
        print(f"  Warning: could not list knowledge collections: {exc}")

    payload = {
        "name": KNOWLEDGE_NAME,
        "description": KNOWLEDGE_DESCRIPTION,
    }
    try:
        resp = client.post(
            f"{base_url}/api/v1/knowledge/create",
            json=payload,
            headers=headers,
            timeout=15,
        )
        if _check_response(resp, "creating knowledge collection"):
            result = resp.json()
            kid = result.get("id", "?")
            print(f"  Created knowledge collection '{KNOWLEDGE_NAME}' (id={kid})")
            return kid
    except Exception as exc:
        print(f"  Failed to create knowledge collection: {exc}")

    return None


def discover_base_model(client: httpx.Client, base_url: str, headers: dict) -> str | None:
    """Try to auto-detect the base model from Ollama/llama.cpp model list."""
    for path in ["/api/tags", "/v1/models", "/api/models"]:
        try:
            resp = client.get(f"{base_url}{path}", headers=headers, timeout=10)
            if resp.status_code != 200:
                continue
            data = resp.json()
            models = data.get("models", data.get("data", []))
            names = []
            for m in models:
                name = m.get("name") or m.get("id") or m.get("model", "")
                if name:
                    names.append(name)
            # Look for qwen
            for n in names:
                if "qwen" in n.lower():
                    return n
            if names:
                return names[0]
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Set up Open WebUI model profiles for SentinelHome")
    parser.add_argument("--url", default=os.environ.get("OPENWEBUI_URL", ""),
                        help="Open WebUI URL (e.g. http://YOUR_HOST_IP:8084)")
    parser.add_argument("--api-key", default=os.environ.get("OPENWEBUI_API_KEY", ""),
                        help="Open WebUI API key")
    parser.add_argument("--base-model", default="",
                        help="Base model ID in Ollama/llama.cpp (e.g. qwen3.5:9b)")
    parser.add_argument("--tool-path", default="",
                        help="Path to openwebui-sentinel-tool.py (auto-detected if omitted)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print payloads without sending")
    args = parser.parse_args()

    url = args.url or input("Open WebUI URL (e.g. http://YOUR_HOST_IP:8084): ").strip()
    api_key = args.api_key or input("Open WebUI API key: ").strip()
    base_model = args.base_model

    if not url:
        print("Error: URL is required")
        sys.exit(1)

    url = url.rstrip("/")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    # Locate the tool file
    tool_path = Path(args.tool_path) if args.tool_path else _DEFAULT_TOOL_PATH
    if tool_path.is_file():
        tool_content = tool_path.read_text(encoding="utf-8")
        print(f"  Tool file: {tool_path} ({len(tool_content)} bytes)")
    else:
        tool_content = None
        print(f"  Warning: Tool file not found at {tool_path}")
        print("  Skipping tool installation. Use --tool-path to specify location.")

    if args.dry_run:
        print("\n=== DRY RUN — Model definitions ===\n")
        for model_def in MODELS:
            payload = {
                "id": model_def["id"],
                "name": model_def["name"],
                "base_model_id": base_model or "<BASE_MODEL>",
                "is_active": True,
                "params": model_def["params"],
                "meta": model_def["meta"],
            }
            print(f"--- {model_def['id']} ---")
            print(json.dumps(payload, indent=2))
            print()
        if tool_content:
            print(f"--- Tool: {TOOL_ID} ---")
            print(f"  Would install tool ({len(tool_content)} bytes)")
            print()
        print("--- Knowledge ---")
        print(f"  Would create collection: {KNOWLEDGE_NAME}")
        return

    client = httpx.Client()

    # Quick auth check before doing anything
    try:
        resp = client.get(f"{url}/api/v1/auths/", headers=headers, timeout=10)
        if resp.status_code == 401:
            print("\nERROR: 401 Unauthorized — your API key is invalid.")
            print("Generate one in Open WebUI: Settings -> Account -> API Keys")
            client.close()
            sys.exit(1)
    except Exception:
        pass  # Endpoint might not exist; proceed and let individual calls handle errors

    # Auto-detect base model if not specified
    if not base_model:
        print(f"\nProbing {url} for available models...")
        detected = discover_base_model(client, url, headers)
        if detected:
            print(f"  Found: {detected}")
            confirm = input(f"  Use '{detected}' as base model? [Y/n]: ").strip().lower()
            if confirm in ("", "y", "yes"):
                base_model = detected
        if not base_model:
            base_model = input("Base model ID (e.g. qwen3.5:9b): ").strip()

    if not base_model:
        print("Error: base model is required")
        sys.exit(1)

    print(f"\n=== Setting up SentinelHome on {url} ===")
    print(f"  Base model: {base_model}")

    # --- Install Tool ---
    tool_ok = False
    if tool_content:
        print("\n--- Installing Tool ---")
        tool_ok = install_tool(client, url, headers, tool_content)
    else:
        print("\n--- Skipping Tool (file not found) ---")

    # --- Create Knowledge collection ---
    print("\n--- Knowledge Collection ---")
    knowledge_id = create_knowledge(client, url, headers)

    # --- Create/update model profiles ---
    print("\n--- Model Profiles ---")
    existing = get_existing_models(client, url, headers)

    created = 0
    updated = 0
    failed = 0

    for model_def in MODELS:
        model_id = model_def["id"]
        print(f"\n  [{model_id}]")
        if model_id in existing:
            if update_model(client, url, headers, model_def, base_model):
                updated += 1
            else:
                failed += 1
        else:
            if create_model(client, url, headers, model_def, base_model):
                created += 1
            else:
                failed += 1

    print(f"\n=== Done: {created} created, {updated} updated, {failed} failed ===")
    if tool_ok:
        print(f"  Tool '{TOOL_ID}' installed")
    if knowledge_id:
        print(f"  Knowledge collection id: {knowledge_id}")

    # --- Config output ---
    print("\n" + "=" * 60)
    print("Add this to your config.yaml:\n")
    print("agent:")
    print("  enabled: true")
    print(f"  url: {url}")
    print("  model: sentinel-analyst")
    print("  chat_model: sentinel-chat")
    print("  investigator_model: sentinel-investigator")
    if knowledge_id:
        print(f"  knowledge_id: {knowledge_id}")
    print()

    if tool_ok:
        print("Configure Tool valves in Open WebUI:")
        print(f"  Workspace -> Tools -> {TOOL_NAME} -> Valves (gear icon)")
        print("  Set:")
        print("    sentinel_url:     http://<sentinel-host>:8890/api/v1")
        print("    sentinel_api_key: <your SentinelHome API key>")
        print()

    client.close()


if __name__ == "__main__":
    main()
