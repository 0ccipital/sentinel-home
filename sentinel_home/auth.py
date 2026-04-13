"""Simple session auth — optional password protection for the dashboard.

If no password is configured, the dashboard is open (zero-friction default).
Once a password is set (via settings page or config), login is required.

Password hash stored in the DB (settings table or a dedicated auth row).
Sessions use a signed cookie (no external session store needed).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time

logger = logging.getLogger(__name__)

# In-memory session store (survives within a process, cleared on restart)
# session_token -> expiry_timestamp
_sessions: dict[str, float] = {}
_SESSION_TTL = 86400 * 7  # 7 days

# NOTE: sessions are bare random tokens stored in _sessions dict.
# There are no signed cookies — the token IS the credential.

# Brute-force protection: track failed login attempts per IP
# ip -> (failure_count, locked_until_timestamp)
_login_failures: dict[str, tuple[int, float]] = {}
_MAX_FAILURES = 5       # lockout after this many consecutive failures
_LOCKOUT_SECONDS = 60   # initial lockout duration
_FAILURE_WINDOW = 300   # reset count after 5 minutes of no failures


def _hash_password(password: str) -> str:
    """Hash a password with a random salt using PBKDF2."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored hash."""
    try:
        salt, dk_hex = stored.split("$", 1)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def get_password_hash() -> str | None:
    """Get the stored password hash from DB, or None if not set."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Baseline  # Reuse baseline table for settings

        with session_scope() as session:
            row = session.query(Baseline).filter(
                Baseline.baseline_type == "_auth",
                Baseline.subject_id == "dashboard_password",
            ).first()
            if row and row.data:
                return row.data.get("hash")
    except Exception:
        pass
    return None


def set_password(new_password: str) -> bool:
    """Set or update the dashboard password."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Baseline

        hashed = _hash_password(new_password)

        with session_scope() as session:
            row = session.query(Baseline).filter(
                Baseline.baseline_type == "_auth",
                Baseline.subject_id == "dashboard_password",
            ).first()
            if row:
                row.data = {"hash": hashed}
            else:
                session.add(Baseline(
                    baseline_type="_auth",
                    subject_id="dashboard_password",
                    data={"hash": hashed},
                    active=True,
                ))
        logger.info("Dashboard password updated")
        return True
    except Exception as exc:
        logger.error("Failed to set password: %s", exc)
        return False


def is_auth_enabled() -> bool:
    """Check if dashboard auth is configured (password set)."""
    return get_password_hash() is not None


def is_login_locked(ip: str) -> bool:
    """Return True if this IP is currently locked out."""
    entry = _login_failures.get(ip)
    if not entry:
        return False
    count, locked_until = entry
    if count >= _MAX_FAILURES and time.time() < locked_until:
        return True
    # Lock has expired — clear the entry
    if time.time() >= locked_until:
        _login_failures.pop(ip, None)
    return False


def _record_login_failure(ip: str) -> None:
    entry = _login_failures.get(ip)
    now = time.time()
    if entry:
        count, locked_until = entry
        # Reset count if last failure was outside the failure window
        if now - locked_until > _FAILURE_WINDOW and count < _MAX_FAILURES:
            count = 0
        count += 1
    else:
        count = 1
    # Exponential backoff: each failure beyond the threshold doubles the lockout
    backoff = _LOCKOUT_SECONDS * (2 ** max(0, count - _MAX_FAILURES))
    locked_until = now + backoff
    _login_failures[ip] = (count, locked_until)
    if count >= _MAX_FAILURES:
        logger.warning("Login locked for IP %s after %d failures (%.0fs)", ip, count, backoff)
    else:
        logger.warning("Login failure %d/%d for IP %s", count, _MAX_FAILURES, ip)


def _clear_login_failures(ip: str) -> None:
    _login_failures.pop(ip, None)


def verify_login(password: str, ip: str = "unknown") -> str | None:
    """Verify password and return a session token, or None on failure.

    ip is used for rate limiting — pass request.client.host.
    """
    if is_login_locked(ip):
        logger.warning("Login attempt blocked — IP %s is locked out", ip)
        return None

    stored = get_password_hash()
    if not stored:
        return None

    if not _verify_password(password, stored):
        _record_login_failure(ip)
        return None

    _clear_login_failures(ip)
    token = secrets.token_urlsafe(32)
    _sessions[token] = time.time() + _SESSION_TTL

    # Prune expired sessions
    now = time.time()
    expired = [k for k, v in _sessions.items() if v < now]
    for k in expired:
        del _sessions[k]

    return token


def invalidate_session(token: str | None) -> None:
    """Remove a session token from the store (called on logout)."""
    if token:
        _sessions.pop(token, None)


def verify_session(token: str | None) -> bool:
    """Check if a session token is valid."""
    if not token:
        return False
    expiry = _sessions.get(token)
    if not expiry:
        return False
    if time.time() > expiry:
        del _sessions[token]
        return False
    return True


def is_authenticated(request) -> bool:
    """Check if a request is authenticated (or auth is disabled)."""
    if not is_auth_enabled():
        return True  # No password set = open access
    token = request.cookies.get("sh_session")
    return verify_session(token)
