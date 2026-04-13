"""LLM adapter — talks to llama.cpp / Ollama / OpenWebUI / any OpenAI-compatible API.

Designed for Qwen3.5-9B (dense, fast, good instruction following).
Recommended temperatures: 0.6 for structured/coding, 1.0 for general.

Two endpoints:
  1. Inference URL (required): Direct to llama.cpp or Ollama for fast micro-tasks.
     Used by actor/critic for triage, classify, evaluate.
  2. OpenWebUI URL (optional): For deep investigation with tools (searxng, etc).
     Used sparingly for NEEDS_MORE_INFO escalation.

The adapter auto-detects the completions path:
  - llama.cpp:  /v1/chat/completions
  - Ollama:     /api/chat  (or /v1/chat/completions with OLLAMA_ORIGINS)
  - Open WebUI: /api/chat/completions

Chat persistence:
  When talking through Open WebUI, include ``chat_id`` and message ``id``
  in the request payload.  Open WebUI then saves the conversation to its
  database, making it visible in the sidebar, searchable, and available
  for Memory/RAG extraction.

The adapter returns raw text. The validator module handles parsing.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

# Timeouts (seconds)
HEALTH_CHECK_TIMEOUT = 5
PATH_PROBE_TIMEOUT = 15
COMPLETE_TIMEOUT = 30     # Micro-task timeout (overridden by config for chat)

# Completions paths to probe, in order of preference
_COMPLETIONS_PATHS = [
    "/v1/chat/completions",      # llama.cpp, vLLM, OpenAI-compat
    "/api/chat/completions",     # Open WebUI
    "/api/chat",                 # Ollama native
]


@dataclass
class LLMResponse:
    """Raw response from the LLM."""
    text: str
    model: str
    tokens_used: int
    latency_seconds: float
    success: bool
    error: str | None = None


class LLMAdapter:
    """OpenAI-compatible chat completions client.

    Supports multiple model profiles for different use cases:
      - model (default): actor/critic micro-tasks — low temp, constrained
      - chat_model: dashboard conversation — higher temp, natural
      - investigator_model: deep investigation — structured JSON, tools
    """

    def __init__(
        self,
        url: str,
        api_key: str = "",
        model: str = "",
        chat_model: str = "",
        investigator_model: str = "",
        timeout: int = 60,
    ):
        self._base_url = url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._chat_model = chat_model or model
        self._investigator_model = investigator_model or model
        self._timeout = timeout
        self._client = httpx.Client(timeout=timeout)

        # Cached completions path (detected on first call)
        self._completions_path: str | None = None

        # Backoff state
        self._consecutive_failures: int = 0
        self._cooldown_until: float = 0  # monotonic time when cooldown expires
        self._max_backoff: float = 60.0  # max seconds between retries

    @property
    def chat_model(self) -> str:
        return self._chat_model

    @property
    def investigator_model(self) -> str:
        return self._investigator_model

    @property
    def model(self) -> str:
        return self._model

    def _record_failure(self) -> None:
        """Record a failure and update backoff state."""
        self._consecutive_failures += 1
        if self._consecutive_failures >= 3:
            # Enter cooldown — skip calls for a while
            backoff = min(2 ** self._consecutive_failures, self._max_backoff)
            self._cooldown_until = time.monotonic() + backoff
            logger.warning(
                "LLM adapter: %d consecutive failures, cooling down for %.0fs",
                self._consecutive_failures, backoff,
            )

    def _record_success(self) -> None:
        """Reset backoff state on success."""
        if self._consecutive_failures > 0:
            logger.info("LLM adapter: recovered after %d failures", self._consecutive_failures)
        self._consecutive_failures = 0
        self._cooldown_until = 0

    def _is_in_cooldown(self) -> bool:
        """Check if we're in a cooldown period after repeated failures."""
        if self._cooldown_until <= 0:
            return False
        if time.monotonic() >= self._cooldown_until:
            # Cooldown expired — allow one attempt
            self._cooldown_until = 0
            return False
        return True

    def reset_backoff(self) -> None:
        """Manually reset backoff state (e.g., after config change)."""
        self._consecutive_failures = 0
        self._cooldown_until = 0

    def _detect_completions_path(self) -> str:
        """Probe the inference server to find the right completions endpoint."""
        if self._completions_path:
            return self._completions_path

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1,
            "temperature": 0,
        }

        for path in _COMPLETIONS_PATHS:
            try:
                resp = self._client.post(
                    f"{self._base_url}{path}",
                    json=payload,
                    headers=headers,
                    timeout=PATH_PROBE_TIMEOUT,
                )
                # Only accept 200 (success) or 400/422 (endpoint exists, bad payload)
                # Reject 404 (not found) and 405 (method not allowed)
                if resp.status_code in (200, 400, 422):
                    self._completions_path = path
                    logger.info("LLM completions path: %s%s (HTTP %d)", self._base_url, path, resp.status_code)
                    return path
                else:
                    logger.debug("Probe %s%s → HTTP %d, skipping", self._base_url, path, resp.status_code)
            except Exception as exc:
                logger.debug("Probe %s%s → %s, skipping", self._base_url, path, exc)
                continue

        # Default to Open WebUI path since that's the configured provider
        self._completions_path = "/api/chat/completions"
        logger.warning(
            "Could not detect completions path, defaulting to %s%s",
            self._base_url, self._completions_path,
        )
        return self._completions_path

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 200,
        temperature: float = 0.6,
    ) -> LLMResponse:
        """Send a chat completion request. Returns raw text."""
        if self._is_in_cooldown():
            return LLMResponse(
                text="", model=self._model, tokens_used=0,
                latency_seconds=0, success=False,
                error="LLM adapter in cooldown after repeated failures",
            )

        path = self._detect_completions_path()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        # Append /no_think to suppress Qwen3.5 reasoning mode for micro-tasks.
        # Reasoning wastes tokens and often leaves content empty for short answers.
        messages.append({"role": "user", "content": user_prompt + "\n/no_think"})

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload = {
            "model": self._model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
            # Qwen3.5: disable thinking at the API level too (Ollama/vLLM)
            "chat_template_kwargs": {"enable_thinking": False},
        }

        start = time.monotonic()
        try:
            resp = self._client.post(
                f"{self._base_url}{path}",
                json=payload,
                headers=headers,
                timeout=min(self._timeout, COMPLETE_TIMEOUT),
            )
            latency = time.monotonic() - start

            if resp.status_code != 200:
                self._record_failure()
                return LLMResponse(
                    text="", model=self._model, tokens_used=0,
                    latency_seconds=latency, success=False,
                    error=f"HTTP {resp.status_code}: {resp.text[:200]}",
                )

            data = resp.json()

            # Ollama native /api/chat returns {"message": {"content": "..."}}
            # OpenAI-compat returns {"choices": [{"message": {"content": "..."}}]}
            if "choices" in data:
                choices = data["choices"]
                if not choices:
                    return LLMResponse(
                        text="", model=self._model, tokens_used=0,
                        latency_seconds=latency, success=False,
                        error="No choices in response",
                    )
                msg = choices[0].get("message", {})
            elif "message" in data:
                # Ollama native format
                msg = data["message"]
            else:
                return LLMResponse(
                    text="", model=self._model, tokens_used=0,
                    latency_seconds=latency, success=False,
                    error=f"Unexpected response format: {list(data.keys())}",
                )

            text = msg.get("content", "")
            # Qwen3.5 with --reasoning-format deepseek: if content is empty,
            # the model may have put its answer in reasoning_content.
            # The reasoning field contains thinking ("The user is asking me...")
            # — only use it as a last resort, and log a warning.
            if not text.strip():
                reasoning = msg.get("reasoning_content", "") or msg.get("reasoning", "")
                if reasoning:
                    # Try to extract just the last line (often the actual answer)
                    lines = [l.strip() for l in reasoning.strip().splitlines() if l.strip()]
                    last_line = lines[-1] if lines else ""
                    logger.warning(
                        "content empty, falling back to reasoning (%d chars). "
                        "Last line: '%.80s'. Consider disabling thinking mode.",
                        len(reasoning), last_line,
                    )
                    # Use the last line if it's short (likely the answer),
                    # otherwise use the full reasoning text
                    text = last_line if len(last_line) < 50 else reasoning

            usage = data.get("usage", {})
            tokens = usage.get("total_tokens", 0)

            if not text.strip():
                logger.warning(
                    "LLM returned empty content — response keys: %s, message keys: %s",
                    list(data.keys()),
                    list(msg.keys()) if "choices" in data else list(data.get("message", {}).keys()),
                )
                return LLMResponse(
                    text="", model=self._model, tokens_used=tokens,
                    latency_seconds=latency, success=False,
                    error="Model returned empty content (check reasoning format)",
                )

            self._record_success()
            return LLMResponse(
                text=text.strip(),
                model=data.get("model", self._model),
                tokens_used=tokens,
                latency_seconds=latency,
                success=True,
            )

        except httpx.TimeoutException:
            self._record_failure()
            return LLMResponse(
                text="", model=self._model, tokens_used=0,
                latency_seconds=time.monotonic() - start, success=False,
                error=f"Timeout after {self._timeout}s",
            )
        except Exception as exc:
            self._record_failure()
            return LLMResponse(
                text="", model=self._model, tokens_used=0,
                latency_seconds=time.monotonic() - start, success=False,
                error=str(exc),
            )

    def chat(
        self,
        messages: list[dict],
        max_tokens: int = 1024,
        temperature: float = 1.0,
        model: str | None = None,
    ) -> LLMResponse:
        """Send a multi-turn chat completion via streaming.

        Uses streaming to accumulate the full response including any
        post-tool-call content from Open WebUI. When the model triggers
        tools (web_search, etc), Open WebUI executes them server-side and
        continues generating — streaming captures the complete output.

        Uses the chat_model by default. Pass model= to override.
        """
        import json as _json

        use_model = model or self._chat_model

        if self._is_in_cooldown():
            return LLMResponse(
                text="", model=use_model, tokens_used=0,
                latency_seconds=0, success=False,
                error="LLM adapter in cooldown after repeated failures",
            )

        path = self._detect_completions_path()

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload = {
            "model": use_model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": True,
        }

        start = time.monotonic()
        try:
            # Use streaming to capture full response including tool-call continuations
            chunks: list[str] = []
            resp_model = use_model
            total_tokens = 0

            with self._client.stream(
                "POST",
                f"{self._base_url}{path}",
                json=payload,
                headers=headers,
            ) as resp:
                if resp.status_code != 200:
                    resp.read()
                    self._record_failure()
                    return LLMResponse(
                        text="", model=use_model, tokens_used=0,
                        latency_seconds=time.monotonic() - start, success=False,
                        error=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    )

                for line in resp.iter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    data_str = line[6:]  # strip "data: "
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        data = _json.loads(data_str)
                    except _json.JSONDecodeError:
                        continue

                    # Extract content delta from SSE chunk
                    if "choices" in data:
                        for choice in data["choices"]:
                            delta = choice.get("delta", {})
                            content = delta.get("content")
                            if content:
                                chunks.append(content)
                            # Note: reasoning_content contains internal thinking —
                            # don't include it in chat output shown to the user.
                    elif "message" in data:
                        # Ollama native streaming format
                        content = data["message"].get("content", "")
                        if content:
                            chunks.append(content)

                    # Capture model name from first chunk
                    if data.get("model"):
                        resp_model = data["model"]

                    # Capture usage from final chunk (if present)
                    usage = data.get("usage")
                    if usage:
                        total_tokens = usage.get("total_tokens", 0)

            latency = time.monotonic() - start
            text = "".join(chunks).strip()

            if not text:
                self._record_failure()
                return LLMResponse(
                    text="", model=resp_model, tokens_used=0,
                    latency_seconds=latency, success=False,
                    error="Empty response from streaming",
                )

            self._record_success()
            return LLMResponse(
                text=text,
                model=resp_model,
                tokens_used=total_tokens,
                latency_seconds=latency,
                success=True,
            )

        except httpx.TimeoutException:
            self._record_failure()
            return LLMResponse(
                text="", model=use_model, tokens_used=0,
                latency_seconds=time.monotonic() - start, success=False,
                error=f"Timeout after {self._timeout}s",
            )
        except Exception as exc:
            self._record_failure()
            return LLMResponse(
                text="", model=use_model, tokens_used=0,
                latency_seconds=time.monotonic() - start, success=False,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Open WebUI chat persistence
    # ------------------------------------------------------------------

    def create_owui_chat(self, title: str = "SentinelHome") -> str | None:
        """Create a new chat in Open WebUI and return its chat_id.

        Returns None if the server doesn't support the /api/v1/chats/new
        endpoint (i.e. we're talking directly to llama.cpp / Ollama).
        """
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        try:
            resp = self._client.post(
                f"{self._base_url}/api/v1/chats/new",
                json={"chat": {"title": title, "models": [self._chat_model or self._model], "messages": [], "history": {}, "tags": []}},
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                chat_id = data.get("id")
                logger.info("Created Open WebUI chat %s (%s)", chat_id, title)
                return chat_id
            logger.warning(
                "create_owui_chat: HTTP %d — response: %.200s",
                resp.status_code, resp.text,
            )
        except Exception as exc:
            logger.warning("create_owui_chat failed: %s", exc)
        return None

    def update_owui_chat(self, chat_id: str, messages: list[dict], title: str | None = None) -> bool:
        """Push the current message history to an existing Open WebUI chat.

        This updates the chat record so the conversation is visible in the
        Open WebUI sidebar with full message content.
        """
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        # Build the history dict Open WebUI expects:
        # { message_id: { id, parentId, childrenIds, role, content, ... } }
        history: dict = {}
        parent_id: str | None = None
        msg_ids: list[str] = []
        owui_messages = []
        for msg in messages:
            mid = msg.get("id") or str(uuid.uuid4())
            msg_ids.append(mid)
            node = {
                "id": mid,
                "parentId": parent_id or "",
                "childrenIds": [],
                "role": msg["role"],
                "content": msg.get("content", ""),
            }
            history[mid] = node
            if parent_id and parent_id in history:
                history[parent_id]["childrenIds"].append(mid)
            parent_id = mid
            owui_messages.append({"id": mid, "role": msg["role"], "content": msg.get("content", "")})

        payload: dict = {
            "chat": {
                "messages": owui_messages,
                "history": {"currentId": msg_ids[-1] if msg_ids else "", "messages": history},
            }
        }
        if title:
            payload["chat"]["title"] = title

        try:
            resp = self._client.post(
                f"{self._base_url}/api/v1/chats/{chat_id}",
                json=payload,
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                return True
            logger.warning(
                "update_owui_chat: HTTP %d — response: %.200s",
                resp.status_code, resp.text,
            )
        except Exception as exc:
            logger.warning("update_owui_chat failed: %s", exc)
        return False

    def chat_with_persistence(
        self,
        messages: list[dict],
        chat_id: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 1.0,
        model: str | None = None,
    ) -> tuple[LLMResponse, str | None]:
        """Like chat(), but includes chat_id so Open WebUI saves the conversation.

        Returns (LLMResponse, chat_id). If chat_id was None and we're talking to
        Open WebUI, a new chat is created first.
        """
        use_model = model or self._chat_model

        # Assign unique IDs to messages so Open WebUI can track them
        for msg in messages:
            if "id" not in msg:
                msg["id"] = str(uuid.uuid4())

        # Create an Open WebUI chat if we don't have one yet
        if chat_id is None:
            chat_id = self.create_owui_chat(title="SentinelHome Chat")

        # Run the normal streaming chat, but inject chat_id and message id
        response = self._chat_with_owui_fields(
            messages=messages,
            chat_id=chat_id,
            max_tokens=max_tokens,
            temperature=temperature,
            model=use_model,
        )

        # After getting the response, update the chat record with full history
        if chat_id and response.success:
            full_messages = list(messages) + [
                {"id": str(uuid.uuid4()), "role": "assistant", "content": response.text}
            ]
            self.update_owui_chat(chat_id, full_messages)

        return response, chat_id

    def _chat_with_owui_fields(
        self,
        messages: list[dict],
        chat_id: str | None,
        max_tokens: int,
        temperature: float,
        model: str,
    ) -> LLMResponse:
        """Internal: streaming chat with Open WebUI persistence fields."""
        import json as _json

        if self._is_in_cooldown():
            return LLMResponse(
                text="", model=model, tokens_used=0,
                latency_seconds=0, success=False,
                error="LLM adapter in cooldown after repeated failures",
            )

        path = self._detect_completions_path()

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload: dict = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": True,
        }

        # Include Open WebUI persistence fields when we have a chat_id
        if chat_id:
            payload["chat_id"] = chat_id
            # Use the last message's id as the request id
            last_user = [m for m in messages if m["role"] == "user"]
            if last_user and "id" in last_user[-1]:
                payload["id"] = last_user[-1]["id"]

        start = time.monotonic()
        try:
            chunks: list[str] = []
            resp_model = model
            total_tokens = 0

            with self._client.stream(
                "POST",
                f"{self._base_url}{path}",
                json=payload,
                headers=headers,
            ) as resp:
                if resp.status_code != 200:
                    resp.read()
                    self._record_failure()
                    return LLMResponse(
                        text="", model=model, tokens_used=0,
                        latency_seconds=time.monotonic() - start, success=False,
                        error=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    )

                for line in resp.iter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        data = _json.loads(data_str)
                    except _json.JSONDecodeError:
                        continue

                    if "choices" in data:
                        for choice in data["choices"]:
                            delta = choice.get("delta", {})
                            content = delta.get("content")
                            if content:
                                chunks.append(content)
                    elif "message" in data:
                        content = data["message"].get("content", "")
                        if content:
                            chunks.append(content)

                    if data.get("model"):
                        resp_model = data["model"]
                    usage = data.get("usage")
                    if usage:
                        total_tokens = usage.get("total_tokens", 0)

            latency = time.monotonic() - start
            text = "".join(chunks).strip()

            if not text:
                self._record_failure()
                return LLMResponse(
                    text="", model=resp_model, tokens_used=0,
                    latency_seconds=latency, success=False,
                    error="Empty response from streaming",
                )

            self._record_success()
            return LLMResponse(
                text=text, model=resp_model, tokens_used=total_tokens,
                latency_seconds=latency, success=True,
            )

        except httpx.TimeoutException:
            self._record_failure()
            return LLMResponse(
                text="", model=model, tokens_used=0,
                latency_seconds=time.monotonic() - start, success=False,
                error=f"Timeout after {self._timeout}s",
            )
        except Exception as exc:
            self._record_failure()
            return LLMResponse(
                text="", model=model, tokens_used=0,
                latency_seconds=time.monotonic() - start, success=False,
                error=str(exc),
            )

    def complete_with_persistence(
        self,
        system_prompt: str,
        user_prompt: str,
        chat_id: str | None = None,
        chat_title: str = "SentinelHome Agent",
        max_tokens: int = 200,
        temperature: float = 0.6,
        chat_messages: list[dict] | None = None,
    ) -> tuple[LLMResponse, str | None, list[dict]]:
        """Like complete(), but logs the exchange to an Open WebUI chat.

        Used by the orchestrator so agent micro-tasks appear in Open WebUI
        chat history. Creates a new chat on first call, reuses it after.
        Pass chat_messages from the previous call to accumulate the full
        conversation rather than overwriting with just the latest exchange.

        Returns (LLMResponse, chat_id, updated_chat_messages).
        """
        # Run the normal (fast, non-streaming) completion
        response = self.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
        )

        # Accumulate messages regardless of success so the history is complete
        accumulated = list(chat_messages) if chat_messages else []
        if system_prompt and not accumulated:
            # Only add system prompt once at the start of a conversation
            accumulated.append({"id": str(uuid.uuid4()), "role": "system", "content": system_prompt})
        accumulated.append({"id": str(uuid.uuid4()), "role": "user", "content": user_prompt})
        if response.success:
            accumulated.append({"id": str(uuid.uuid4()), "role": "assistant", "content": response.text})
        else:
            accumulated.append({"id": str(uuid.uuid4()), "role": "assistant",
                                 "content": f"[error: {response.error}]"})

        if not response.success:
            return response, chat_id, accumulated

        # Log to Open WebUI chat (best-effort, don't fail the task)
        try:
            if chat_id is None:
                chat_id = self.create_owui_chat(title=chat_title)

            if chat_id:
                ok = self.update_owui_chat(chat_id, accumulated, title=chat_title)
                if not ok:
                    logger.warning(
                        "update_owui_chat failed for chat %s (title=%s) — "
                        "check Open WebUI API compatibility",
                        chat_id, chat_title,
                    )
        except Exception as exc:
            logger.warning("Failed to log completion to Open WebUI: %s", exc)

        return response, chat_id, accumulated

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def is_available(self) -> bool:
        """Check if the LLM endpoint is reachable."""
        try:
            # Try health endpoint first (llama.cpp), then models list
            for path in ["/health", "/v1/models", "/api/tags", "/api/models"]:
                try:
                    resp = self._client.get(
                        f"{self._base_url}{path}",
                        headers=(
                            {"Authorization": f"Bearer {self._api_key}"}
                            if self._api_key else {}
                        ),
                        timeout=HEALTH_CHECK_TIMEOUT,
                    )
                    if resp.status_code == 200:
                        return True
                except Exception:
                    continue
            return False
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_adapter: LLMAdapter | None = None


def get_llm_adapter() -> LLMAdapter | None:
    """Get the configured LLM adapter, or None if agent is disabled."""
    global _adapter
    if _adapter is not None:
        return _adapter

    try:
        from sentinel_home.config import get_settings
        settings = get_settings()
        if not settings.agent.enabled or not settings.agent.url:
            return None

        _adapter = LLMAdapter(
            url=settings.agent.url,
            api_key=settings.agent.api_key,
            model=settings.agent.model,
            chat_model=settings.agent.chat_model,
            investigator_model=settings.agent.investigator_model,
            timeout=settings.agent.timeout_seconds,
        )
        return _adapter
    except Exception as exc:
        logger.error("Failed to create LLM adapter: %s", exc)
        return None
