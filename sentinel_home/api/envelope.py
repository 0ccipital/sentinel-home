"""Standard JSON response envelope helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def ok_envelope(data: Any) -> dict:
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }


def error_envelope(error_code: str, message: str) -> dict:
    return {
        "status": "error",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error_code": error_code,
        "message": message,
    }
