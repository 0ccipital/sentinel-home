"""X-API-Key authentication middleware.

GET requests to /api/v1/ are allowed without auth (read-only, LAN-only deployment).
POST/PUT/DELETE/PATCH requests always require the key.
All /api/ paths are covered (including /api/logs/).
"""

from __future__ import annotations

import hmac

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from sentinel_home.config import get_settings
from sentinel_home.api.envelope import error_envelope


class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Enforce on all /api/ paths (covers /api/v1/ and /api/logs/)
        if not path.startswith("/api/"):
            return await call_next(request)

        settings = get_settings()
        api_key = settings.server.api_key

        # If no key is configured, skip auth entirely (dev mode)
        if not api_key:
            return await call_next(request)

        # GET requests are allowed without auth (read-only, LAN-only)
        if request.method == "GET":
            return await call_next(request)

        # All mutating methods require the key — use constant-time comparison
        provided = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(provided.encode(), api_key.encode()):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content=error_envelope("UNAUTHORIZED", "Valid X-API-Key header required"),
            )

        return await call_next(request)
