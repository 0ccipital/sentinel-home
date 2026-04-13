"""Dashboard HTML routes — Jinja2 templates + HTMX partials."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from html import escape as h
from pathlib import Path

from typing import Optional

from fastapi import APIRouter, Request, Form, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sse_starlette.sse import EventSourceResponse
from starlette.middleware.base import BaseHTTPMiddleware

router = APIRouter()

_templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_templates_dir))


# ---------------------------------------------------------------------------
# Dashboard auth middleware — enforces login when a password is set
# ---------------------------------------------------------------------------

class DashboardAuthMiddleware(BaseHTTPMiddleware):
    """Redirect unauthenticated dashboard requests to /login.

    Only active when a dashboard password has been set (via settings page).
    API endpoints (/api/) are handled separately by APIKeyMiddleware.
    Static files and the login page itself are always accessible.
    """

    # Paths that are always accessible without login
    _public_paths = frozenset({"/login", "/static", "/api/", "/favicon.ico"})

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Always allow public paths
        if any(path.startswith(p) for p in self._public_paths):
            return await call_next(request)

        # Check if auth is enabled
        from sentinel_home.auth import is_auth_enabled, verify_session
        if not is_auth_enabled():
            return await call_next(request)

        # Check session cookie
        token = request.cookies.get("sh_session")
        if verify_session(token):
            return await call_next(request)

        # Not authenticated — redirect to login
        # For HTMX partial requests, return 401 so the page doesn't break
        if request.headers.get("HX-Request"):
            return HTMLResponse(
                '<p class="text-muted text-sm">Session expired. '
                '<a href="/login">Log in</a></p>',
                status_code=401,
            )
        return RedirectResponse(url="/login", status_code=302)


# ---------------------------------------------------------------------------
# Login / Logout routes
# ---------------------------------------------------------------------------

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Serve the login form. If auth is not enabled, redirect to dashboard."""
    from sentinel_home.auth import is_auth_enabled
    if not is_auth_enabled():
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, password: str = Form(...)):
    """Validate password and set session cookie."""
    from sentinel_home.auth import verify_login, is_login_locked
    ip = request.client.host if request.client else "unknown"
    if is_login_locked(ip):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Too many failed attempts. Try again shortly."},
            status_code=429,
        )
    token = verify_login(password, ip=ip)
    if not token:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Incorrect password"},
            status_code=401,
        )
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key="sh_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=86400 * 7,  # 7 days
    )
    return response


@router.get("/logout")
async def logout(request: Request):
    """Invalidate server-side session token and redirect to login."""
    from sentinel_home.auth import invalidate_session
    token = request.cookies.get("sh_session")
    invalidate_session(token)
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("sh_session")
    return response


# ---------------------------------------------------------------------------
# Helper: resolve device MAC to a display name
# ---------------------------------------------------------------------------

def _device_name(mac: str | None) -> str:
    """Resolve a MAC to 'label (IP)' or 'vendor (IP)' or just the MAC."""
    if not mac:
        return "—"
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Device
        from sentinel_home.utils import device_display_name
        with session_scope() as session:
            d = session.query(Device).filter(Device.mac == mac).first()
            if not d:
                return mac
            return device_display_name(
                mac=mac, label=d.label, vendor=d.vendor,
                hostnames=d.hostnames, ip=d.ip,
            )
    except Exception:
        return mac


# ---------------------------------------------------------------------------
# Helper: format timestamps for templates
# ---------------------------------------------------------------------------

def _ago(dt: datetime | None) -> str:
    """Human-readable time ago string."""
    if not dt:
        return "never"
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = now - dt
    secs = int(delta.total_seconds())
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


def _fmt_ts(dt: datetime | None) -> str:
    if not dt:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%H:%M:%S")


# Register as Jinja2 globals
templates.env.globals["ago"] = _ago
templates.env.globals["fmt_ts"] = _fmt_ts


# ---------------------------------------------------------------------------
# Generic note rendering helper
# ---------------------------------------------------------------------------

def _render_notes(entity_type: str, entity_id: str) -> str:
    """Render notes for any entity as an HTML timeline."""
    from sentinel_home.database import session_scope
    from sentinel_home.models import Note

    with session_scope() as session:
        notes = session.query(Note).filter(
            Note.entity_type == entity_type,
            Note.entity_id == entity_id,
        ).order_by(Note.ts.desc()).limit(50).all()

        note_data = [
            {"ts": n.ts, "source": n.source, "text": n.text}
            for n in notes
        ]

    if not note_data:
        return '<p class="text-xs text-muted">No notes yet.</p>'

    source_colors = {
        "user": "var(--sh-accent)",
        "agent": "var(--sh-yellow)",
        "chat": "var(--sh-green)",
        "system": "var(--sh-text-muted)",
    }

    html = ""
    for n in note_data:
        color = source_colors.get(n["source"], "var(--sh-text-muted)")
        ts_str = n["ts"].strftime("%Y-%m-%d %H:%M") if n["ts"] else ""
        html += f'''<div style="border-left:2px solid {color};padding:0.25rem 0 0.25rem 0.5rem;margin-bottom:0.4rem">
            <span class="text-xs text-muted">{ts_str} &middot; {h(n["source"])}</span>
            <p class="text-sm" style="margin:0.1rem 0 0">{h(n["text"])}</p>
        </div>'''
    return html


# ---------------------------------------------------------------------------
# Full pages
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request, "title": "Overview", "active_page": "overview",
    })


@router.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request):
    return templates.TemplateResponse("devices.html", {
        "request": request, "title": "Devices", "active_page": "devices",
    })


@router.get("/events", response_class=HTMLResponse)
async def events_page(request: Request):
    return templates.TemplateResponse("events.html", {
        "request": request, "title": "Events", "active_page": "events",
    })


@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    return templates.TemplateResponse("alerts.html", {
        "request": request, "title": "Alerts", "active_page": "alerts",
    })


@router.get("/wan", response_class=HTMLResponse)
async def wan_page(request: Request):
    return templates.TemplateResponse("wan.html", {
        "request": request, "title": "WAN", "active_page": "wan",
    })


@router.get("/logs", response_class=HTMLResponse)
async def log_viewer(request: Request):
    return templates.TemplateResponse("logs.html", {
        "request": request, "title": "Logs", "active_page": "logs",
    })


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    from sentinel_home.auth import is_auth_enabled
    return templates.TemplateResponse("settings.html", {
        "request": request, "title": "Settings", "active_page": "settings",
        "auth_enabled": is_auth_enabled(),
    })


# ---------------------------------------------------------------------------
# HTMX Partials — status badge (header)
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/status-badge", response_class=HTMLResponse)
async def partial_status_badge():
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Alert, Job
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)

        with session_scope() as session:
            pending = session.query(Job).filter(Job.status == "pending").count()
            recent_alerts = session.query(Alert).filter(
                Alert.ts >= hour_ago, Alert.sent == False
            ).count()

        parts = []
        if recent_alerts > 0:
            parts.append(f'<span class="badge badge-err">{recent_alerts} alert{"s" if recent_alerts != 1 else ""}</span>')
        if pending > 0:
            parts.append(f'<span class="badge badge-warn">queue: {pending}</span>')
        if not parts:
            parts.append('<span class="badge badge-ok">all clear</span>')
        return "\n".join(parts)
    except Exception:
        return '<span class="badge badge-info">—</span>'


# ---------------------------------------------------------------------------
# HTMX Partials — overview stats
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/overview-stats", response_class=HTMLResponse)
async def partial_overview_stats():
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Device, Event, Alert, Job, EventRollup
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)

        with session_scope() as session:
            device_count = session.query(Device).count()
            event_count = session.query(Event).filter(Event.ts >= hour_ago).count()
            alert_count = session.query(Alert).filter(Alert.sent == False).count()
            queue_depth = session.query(Job).filter(Job.status == "pending").count()

            # WAN blocks from rollups (last hour)
            wan_rollups = (
                session.query(EventRollup)
                .filter(EventRollup.hour >= hour_ago, EventRollup.event_type == "fw_wan_block")
                .all()
            )
            wan_count = sum(r.count for r in wan_rollups)

        # Also check in-memory counters
        try:
            from sentinel_home.metrics.counters import get_counters
            snap = get_counters().get_snapshot()
            for key, count in snap.items():
                if "fw_wan_block" in key:
                    wan_count += count
        except Exception:
            pass

        def _color(val, warn=5, err=20):
            if val >= err:
                return "var(--sh-red)"
            if val >= warn:
                return "var(--sh-yellow)"
            return "var(--sh-accent)"

        return f'''
        <div class="sh-grid" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr))">
          <div class="sh-card sh-stat">
            <div class="value" style="color:var(--sh-accent)">{device_count}</div>
            <div class="label">Devices</div>
          </div>
          <div class="sh-card sh-stat">
            <div class="value" style="color:var(--sh-accent)">{event_count}</div>
            <div class="label">Events (1h)</div>
          </div>
          <div class="sh-card sh-stat">
            <div class="value" style="color:{_color(alert_count, 1, 5)}">{alert_count}</div>
            <div class="label">Unread Alerts</div>
          </div>
          <div class="sh-card sh-stat">
            <div class="value" style="color:{_color(wan_count, 50, 200)}">{wan_count:,}</div>
            <div class="label">WAN Blocks (1h)</div>
          </div>
          <div class="sh-card sh-stat">
            <div class="value" style="color:{_color(queue_depth, 5, 20)}">{queue_depth}</div>
            <div class="label">Queue</div>
          </div>
        </div>'''
    except Exception as exc:
        return f'<div class="sh-card"><p class="text-muted text-sm">Stats unavailable: {exc}</p></div>'


# ---------------------------------------------------------------------------
# HTMX Partials — activity chart data (JSON)
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/activity-data")
async def partial_activity_data():
    """Return 24h hourly data for the activity chart."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Event, EventRollup, Alert
        from sqlalchemy import func

        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(hours=24)

        labels = []
        events_data = []
        wan_data = []
        alerts_data = []

        with session_scope() as session:
            for i in range(24):
                h_start = day_ago + timedelta(hours=i)
                h_end = h_start + timedelta(hours=1)
                label = h_start.strftime("%H:%M")
                labels.append(label)

                # Events count
                ec = session.query(func.count(Event.id)).filter(
                    Event.ts >= h_start, Event.ts < h_end
                ).scalar() or 0
                events_data.append(ec)

                # WAN blocks from rollups
                wc = session.query(func.coalesce(func.sum(EventRollup.count), 0)).filter(
                    EventRollup.hour >= h_start, EventRollup.hour < h_end,
                    EventRollup.event_type == "fw_wan_block",
                ).scalar() or 0
                wan_data.append(wc)

                # Alerts
                ac = session.query(func.count(Alert.id)).filter(
                    Alert.ts >= h_start, Alert.ts < h_end
                ).scalar() or 0
                alerts_data.append(ac)

        return {
            "labels": labels,
            "events": events_data,
            "wan_blocks": wan_data,
            "alerts": alerts_data,
        }
    except Exception:
        return {"labels": [], "events": [], "wan_blocks": [], "alerts": []}


# ---------------------------------------------------------------------------
# HTMX Partials — collectors
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/collectors", response_class=HTMLResponse)
async def partial_collectors():
    try:
        from sentinel_home.main import _collectors
        if not _collectors:
            return '<h2>Collectors</h2><p class="text-muted text-sm">Dev mode — collectors not running.</p>'

        rows = ""
        for c in _collectors:
            stats = c.get_stats()
            running = stats.get("running", False)
            dot = '<span class="sev-low">&#9679;</span>' if running else '<span class="sev-high">&#9679;</span>'
            err = stats.get("error_count", 0)
            err_html = f'<span class="sev-high">{err}</span>' if err > 0 else "0"
            rows += f'''<tr>
                <td>{c.name}</td>
                <td>{dot} {"running" if running else "stopped"}</td>
                <td>{stats.get("event_count", 0):,}</td>
                <td>{err_html}</td>
            </tr>'''

        return f'''<h2>Collectors</h2>
        <table class="sh-table">
            <tr><th>Name</th><th>Status</th><th>Events</th><th>Errors</th></tr>
            {rows}
        </table>'''
    except Exception as exc:
        return f'<h2>Collectors</h2><p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# HTMX Partials — recent alerts
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/recent-alerts", response_class=HTMLResponse)
async def partial_recent_alerts():
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Alert, Device

        with session_scope() as session:
            alerts = (
                session.query(Alert)
                .order_by(Alert.ts.desc())
                .limit(50)
                .all()
            )

            # Resolve device names
            device_macs = {a.device_id for a in alerts if a.device_id}
            dev_names = {}
            if device_macs:
                for d in session.query(Device).filter(Device.mac.in_(device_macs)).all():
                    name = d.label or d.vendor or d.mac[:8]
                    if d.ip:
                        name += f" ({d.ip})"
                    dev_names[d.mac] = name

            alert_data = [{
                "id": a.id, "rule_name": a.rule_name, "device_id": a.device_id,
                "severity": a.severity, "ts": a.ts, "message": a.message,
                "sent": a.sent,
                "device_name": dev_names.get(a.device_id, a.device_id or "—"),
            } for a in alerts]

        if not alert_data:
            return '<h2>Recent Alerts</h2><p class="text-muted text-sm">No alerts yet.</p>'

        unacked = sum(1 for a in alert_data if not a["sent"])
        rows = ""
        for a in alert_data:
            sev_cls = f"sev-{a['severity']}" if a['severity'] else "sev-info"
            ack_cls = ' style="opacity:0.5"' if a['sent'] else ""
            rows += f'''<tr{ack_cls}>
                <td class="nowrap text-xs text-muted">{_fmt_ts(a["ts"])}</td>
                <td><span class="{sev_cls}">{a["severity"] or "?"}</span></td>
                <td class="text-xs">{h(a["rule_name"])}</td>
                <td class="text-xs">{h(a["device_name"])}</td>
                <td class="text-sm">{h((a["message"] or "—")[:100])}</td>
            </tr>'''

        return f'''<h2>Recent Alerts <span class="badge badge-err">{unacked}</span></h2>
        <div style="max-height:320px;overflow-y:auto">
        <table class="sh-table">
            <tr><th>Time</th><th>Sev</th><th>Rule</th><th>Device</th><th>Message</th></tr>
            {rows}
        </table></div>
        <a href="/alerts" class="text-xs text-accent" style="text-decoration:none">View all alerts &rarr;</a>'''
    except Exception as exc:
        return f'<h2>Recent Alerts</h2><p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# HTMX Partials — recent events
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/recent-events", response_class=HTMLResponse)
async def partial_recent_events():
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Event

        with session_scope() as session:
            events = (
                session.query(Event)
                .order_by(Event.ts.desc())
                .limit(30)
                .all()
            )
            event_data = [{
                "id": e.id, "ts": e.ts, "source": e.source,
                "event_type": e.event_type, "severity": e.severity,
                "message": e.message, "device_id": e.device_id,
            } for e in events]

        if not event_data:
            return '<h2>Event Feed</h2><p class="text-muted text-sm">No events yet.</p>'

        src_colors = {
            "syslog_file": "#58a6ff", "syslog_server": "#58a6ff",
            "sniff": "#3fb950", "nmap": "#bc8cff",
            "pihole": "#ff7b72", "plex": "#f0883e", "rule_engine": "#8b949e",
        }

        rows = ""
        for e in event_data:
            sev_cls = f"sev-{e['severity']}" if e['severity'] else "sev-info"
            color = src_colors.get(e["source"], "#8b949e")
            rows += f'''<tr>
                <td class="nowrap text-xs text-muted">{_fmt_ts(e["ts"])}</td>
                <td><span style="color:{color}" class="text-xs" style="font-weight:600">{h(e["source"])}</span></td>
                <td class="text-xs text-muted">{h(e["event_type"])}</td>
                <td class="{sev_cls} text-xs">{h(e["severity"] or "")}</td>
                <td class="text-sm">{h((e["message"] or "—")[:100])}</td>
                <td>
                  <button class="sh-btn sh-btn-warn" title="Flag as concerning"
                    hx-post="/dashboard/actions/flag/{e["id"]}" hx-swap="outerHTML">flag</button>
                  <button class="sh-btn" title="Suppress this pattern"
                    hx-post="/dashboard/actions/suppress/{e["id"]}" hx-swap="outerHTML">suppress</button>
                </td>
            </tr>'''

        return f'''<h2>Event Feed <span class="text-muted text-xs">latest 30</span></h2>
        <div style="max-height:400px;overflow-y:auto">
        <table class="sh-table">
            <tr><th>Time</th><th>Source</th><th>Type</th><th>Sev</th><th>Message</th><th></th></tr>
            {rows}
        </table>
        </div>
        <a href="/events" class="text-xs text-accent" style="text-decoration:none">View all events &rarr;</a>'''
    except Exception as exc:
        return f'<h2>Event Feed</h2><p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# User actions — Device update
# ---------------------------------------------------------------------------

_EDITABLE_DEVICE_FIELDS = {"label", "device_type", "network_role", "device_notes", "expected_behavior"}


@router.post("/dashboard/actions/update-device/{mac}", response_class=HTMLResponse)
async def action_update_device(mac: str, field: str = Form(...), value: str = Form("")):
    """Update an editable device field."""
    if field not in _EDITABLE_DEVICE_FIELDS:
        return HTMLResponse(f'<span class="text-xs sev-high">field "{h(field)}" not editable</span>', status_code=400)
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Device

        with session_scope() as session:
            device = session.query(Device).filter(Device.mac == mac).first()
            if not device:
                return HTMLResponse('<span class="text-xs text-muted">device not found</span>', status_code=404)
            setattr(device, field, value.strip() or None)
            device.updated_by = "user"

        return HTMLResponse(status_code=204)  # No content — HTMX swap="none"
    except Exception as exc:
        return HTMLResponse(f'<span class="text-xs sev-high">Error: {h(str(exc))}</span>', status_code=500)


# ---------------------------------------------------------------------------
# User actions — Add device note (dashboard form handler)
# ---------------------------------------------------------------------------

@router.post("/dashboard/actions/add-device-note/{mac}", response_class=HTMLResponse)
async def action_add_device_note(mac: str, text: str = Form("")):
    """Add a note to a device (form-encoded from dashboard)."""
    if not text.strip():
        return HTMLResponse(status_code=204)
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Device, Note

        with session_scope() as session:
            device = session.query(Device).filter(Device.mac == mac).first()
            if not device:
                return HTMLResponse('<span class="text-xs text-muted">device not found</span>', status_code=404)
            session.add(Note(
                entity_type="device",
                entity_id=mac,
                text=text.strip(),
                source="user",
            ))

        return HTMLResponse(status_code=204)
    except Exception as exc:
        return HTMLResponse(f'<span class="text-xs sev-high">Error: {h(str(exc))}</span>', status_code=500)


# ---------------------------------------------------------------------------
# User actions — Flag / Suppress (user-in-the-loop)
# ---------------------------------------------------------------------------

@router.post("/dashboard/actions/flag/{event_id}", response_class=HTMLResponse)
async def action_flag_event(event_id: int):
    """Flag an event as concerning — bumps priority, queues for investigation.

    Also increments the originating rule's true_positive_count, feeding
    the critic's evaluation loop with real user feedback.
    """
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Event, Job, Note, Rule

        with session_scope() as session:
            event = session.query(Event).filter(Event.id == event_id).first()
            if not event:
                return '<span class="text-xs text-muted">not found</span>'

            # Feedback: flag = confirmed true positive for the rule
            if event.rule_id:
                rule = session.query(Rule).filter(Rule.id == event.rule_id).first()
                if rule:
                    rule.true_positive_count = (rule.true_positive_count or 0) + 1

            # Create a high-priority investigation job
            session.add(Job(
                source="user",
                rule_name="user_flagged",
                device_id=event.device_id,
                priority=0,  # highest
                context={
                    "event_id": event.id,
                    "event_type": event.event_type,
                    "message": event.message or "",
                    "flagged_by": "user",
                },
            ))

            # Record a note
            session.add(Note(
                entity_type="event_type",
                entity_id=event.event_type,
                source="user",
                text=f"User flagged event #{event_id} for investigation",
            ))

        return '<span class="badge badge-warn">flagged</span>'
    except Exception:
        return '<span class="text-xs sev-high">error</span>'


@router.post("/dashboard/actions/suppress/{event_id}", response_class=HTMLResponse)
async def action_suppress_event(event_id: int):
    """Suppress an event pattern — creates a suppression pattern.

    Also increments the originating rule's false_positive_count, feeding
    the critic's evaluation loop with real user feedback.
    """
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Event, Note, Pattern, Rule

        with session_scope() as session:
            event = session.query(Event).filter(Event.id == event_id).first()
            if not event:
                return '<span class="text-xs text-muted">not found</span>'

            # Feedback: suppress = false positive for the rule
            if event.rule_id:
                rule = session.query(Rule).filter(Rule.id == event.rule_id).first()
                if rule:
                    rule.false_positive_count = (rule.false_positive_count or 0) + 1

            # Create suppression pattern
            pattern_name = f"suppress_{event.event_type}_{event.device_id or 'any'}"
            existing = session.query(Pattern).filter(Pattern.name == pattern_name).first()
            if not existing:
                session.add(Pattern(
                    name=pattern_name,
                    pattern_type="suppression",
                    scope=event.device_id or "*",
                    definition={
                        "event_type": event.event_type,
                        "source": event.source,
                        "created_from_event": event.id,
                    },
                    confidence=1.0,
                    sample_count=1,
                    created_by="user",
                    notes=f"User suppressed from dashboard. Original: {(event.message or '')[:200]}",
                ))

            # Record a note
            note_text = f"User suppressed {event.event_type} events"
            if event.device_id:
                note_text += f" for device {event.device_id}"
            session.add(Note(
                entity_type="event_type",
                entity_id=event.event_type,
                source="user",
                text=note_text,
            ))

        return '<span class="badge badge-info">suppressed</span>'
    except Exception:
        return '<span class="text-xs sev-high">error</span>'


# ---------------------------------------------------------------------------
# User actions — General notes (Network Notes on overview)
# ---------------------------------------------------------------------------

def _render_general_notes(notes: list) -> str:
    """Render general notes as an HTML list."""
    if not notes:
        return '<p class="text-muted text-sm">No notes yet.</p>'
    items = ""
    for n in notes:
        ts = n.ts.strftime("%Y-%m-%d %H:%M") if n.ts else ""
        source_badge = f'<span class="text-xs text-muted">[{h(n.source)}]</span> ' if n.source != "user" else ""
        items += (
            f'<li style="margin-bottom:0.3rem;font-size:0.85rem">'
            f'<span class="text-xs text-muted">{ts}</span> '
            f'{source_badge}{h(n.text)}'
            f'</li>'
        )
    return f'<ul style="list-style:none;padding:0;margin:0">{items}</ul>'


@router.get("/dashboard/partials/general-notes", response_class=HTMLResponse)
async def partial_general_notes():
    """Return rendered general notes."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Note

        with session_scope() as session:
            notes = (
                session.query(Note)
                .filter(Note.entity_type == "general")
                .order_by(Note.ts.desc())
                .limit(50)
                .all()
            )
            return _render_general_notes(notes)
    except Exception as exc:
        return f'<p class="text-muted text-sm">Error: {h(str(exc))}</p>'


@router.post("/dashboard/actions/add-general-note", response_class=HTMLResponse)
async def action_add_general_note(text: str = Form("")):
    """Add a general network note and return the updated list."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Note

        if text.strip():
            with session_scope() as session:
                session.add(Note(
                    entity_type="general",
                    entity_id=None,
                    source="user",
                    text=text.strip(),
                ))

        # Return updated notes list
        with session_scope() as session:
            notes = (
                session.query(Note)
                .filter(Note.entity_type == "general")
                .order_by(Note.ts.desc())
                .limit(50)
                .all()
            )
            return _render_general_notes(notes)
    except Exception as exc:
        return f'<p class="text-muted text-sm">Error: {h(str(exc))}</p>'


# ---------------------------------------------------------------------------
# Log viewer API (kept from v0.3)
# ---------------------------------------------------------------------------

@router.get("/api/logs/recent")
async def api_logs_recent(limit: int = 500):
    from sentinel_home.main import get_memory_handler
    handler = get_memory_handler()
    if not handler:
        return {"lines": [], "count": 0}
    lines = handler.get_lines(limit)
    return {"lines": lines, "count": len(lines)}


@router.get("/api/logs/stream")
async def api_logs_stream(request: Request):
    from sentinel_home.main import get_memory_handler
    handler = get_memory_handler()
    if not handler:
        return HTMLResponse("Log handler not available", status_code=503)

    queue = handler.subscribe()
    if queue is None:
        return HTMLResponse("Too many log viewers connected", status_code=429)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    line = await asyncio.wait_for(queue.get(), timeout=30)
                    yield {"event": "log", "data": line}
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": ""}
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            handler.unsubscribe(queue)

    return EventSourceResponse(event_generator())


# ---------------------------------------------------------------------------
# HTMX Partials — events table (full page, with filters)
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/events-table", response_class=HTMLResponse)
async def partial_events_table(source: str = "", severity: str = "", search: str = ""):
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Event, Device

        with session_scope() as session:
            q = session.query(Event).order_by(Event.ts.desc())
            if source:
                q = q.filter(Event.source == source)
            if severity:
                q = q.filter(Event.severity == severity)
            if search:
                q = q.filter(Event.message.ilike(f"%{search}%"))
            events = q.limit(100).all()

            # Resolve device names in bulk
            device_macs = {e.device_id for e in events if e.device_id}
            dev_names = {}
            if device_macs:
                for d in session.query(Device).filter(Device.mac.in_(device_macs)).all():
                    name = d.label or d.vendor or d.mac[:8]
                    if d.ip:
                        name += f" ({d.ip})"
                    dev_names[d.mac] = name

            event_data = [{
                "id": e.id, "ts": e.ts, "source": e.source,
                "event_type": e.event_type, "severity": e.severity,
                "message": e.message, "device_id": e.device_id,
                "category": e.category, "raw": e.raw,
                "device_name": dev_names.get(e.device_id, e.device_id or ""),
            } for e in events]

        if not event_data:
            return '<p class="text-muted text-sm">No events match filters.</p>'

        src_colors = {
            "syslog_file": "#58a6ff", "syslog_server": "#58a6ff",
            "sniff": "#3fb950", "nmap": "#bc8cff",
            "pihole": "#ff7b72", "plex": "#f0883e",
        }

        rows = ""
        for e in event_data:
            sev_cls = f"sev-{e['severity']}" if e['severity'] else "sev-info"
            color = src_colors.get(e["source"], "#8b949e")
            row_id = f"ev-{e['id']}"

            rows += f'''<tr class="expand-row" onclick="document.getElementById('{row_id}').classList.toggle('open')">
                <td class="nowrap text-xs text-muted">{_fmt_ts(e["ts"])}</td>
                <td><span style="color:{color}" class="text-xs">{h(e["source"])}</span></td>
                <td class="text-xs text-muted">{h(e["event_type"])}</td>
                <td class="{sev_cls} text-xs">{h(e["severity"] or "")}</td>
                <td class="text-sm">{h((e["message"] or "—")[:120])}</td>
                <td class="text-xs">{h(e["device_name"][:30])}</td>
                <td class="nowrap" onclick="event.stopPropagation()">
                  <button class="sh-btn sh-btn-warn"
                    hx-post="/dashboard/actions/flag/{e["id"]}" hx-swap="outerHTML">flag</button>
                  <button class="sh-btn"
                    hx-post="/dashboard/actions/suppress/{e["id"]}" hx-swap="outerHTML">suppress</button>
                </td>
            </tr>'''

            # Expandable detail row
            detail_parts = []
            detail_parts.append(f'<dt>Full Message</dt><dd>{h(e["message"] or "—")}</dd>')
            detail_parts.append(f'<dt>Time</dt><dd>{e["ts"].strftime("%Y-%m-%d %H:%M:%S") if e["ts"] else "—"}</dd>')
            detail_parts.append(f'<dt>Source</dt><dd>{h(e["source"])}</dd>')
            detail_parts.append(f'<dt>Type</dt><dd>{h(e["event_type"])}</dd>')
            detail_parts.append(f'<dt>Category</dt><dd>{h(e["category"] or "—")}</dd>')
            if e["device_id"]:
                detail_parts.append(f'<dt>Device</dt><dd>{h(e["device_name"])} <span class="mono text-xs text-muted">{h(e["device_id"])}</span></dd>')
            if e.get("raw") and isinstance(e["raw"], dict):
                import json as _json
                raw_str = _json.dumps(e["raw"], indent=2, default=str)
                if len(raw_str) > 20:
                    detail_parts.append(f'<dt>Raw Data</dt><dd><pre class="mono text-xs" style="margin:0;max-height:200px;overflow:auto;white-space:pre-wrap">{h(raw_str[:2000])}</pre></dd>')

            rows += f'''<tr id="{row_id}" class="expand-detail">
                <td colspan="7"><dl class="detail-grid">{"".join(detail_parts)}</dl></td>
            </tr>'''

        return f'''<p class="text-xs text-muted mb-1">{len(event_data)} events — click a row to expand</p>
        <div style="max-height:calc(100vh - 260px);overflow-y:auto">
        <table class="sh-table">
            <tr><th>Time</th><th>Source</th><th>Type</th><th>Sev</th><th>Message</th><th>Device</th><th></th></tr>
            {rows}
        </table></div>'''
    except Exception as exc:
        return f'<p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# HTMX Partials — devices table
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/devices-table", response_class=HTMLResponse)
async def partial_devices_table(dtype: str = "", search: str = ""):
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Device

        with session_scope() as session:
            q = session.query(Device).order_by(Device.last_seen.desc())
            if dtype:
                q = q.filter(Device.device_type == dtype)
            if search:
                term = f"%{search}%"
                q = q.filter(
                    (Device.mac.ilike(term)) |
                    (Device.ip.ilike(term)) |
                    (Device.vendor.ilike(term)) |
                    (Device.label.ilike(term))
                )
            devices = q.limit(200).all()
            device_data = [{
                "mac": d.mac, "ip": d.ip, "vendor": d.vendor,
                "device_type": d.device_type, "label": d.label,
                "os_family": d.os_family, "connection_type": d.connection_type,
                "network_role": d.network_role, "last_seen": d.last_seen,
                "first_seen": d.first_seen, "ap": d.ap,
            } for d in devices]

        if not device_data:
            return '<p class="text-muted text-sm">No devices found.</p>'

        type_icons = {
            "router": "&#128230;", "ap": "&#128225;", "switch": "&#128260;",
            "infrastructure": "&#9881;", "server": "&#128421;", "desktop": "&#128187;",
            "laptop": "&#128187;", "phone": "&#128241;", "tablet": "&#128241;",
            "iot": "&#129302;", "media": "&#127916;",
        }

        rows = ""
        for d in device_data:
            icon = type_icons.get(d["device_type"] or "", "")
            label_html = f'<strong>{h(d["label"])}</strong>' if d["label"] else '<span class="text-muted">—</span>'
            conn = ""
            if d["connection_type"] == "wifi":
                conn = '<span class="text-xs" style="color:var(--sh-green)">wifi</span>'
            elif d["connection_type"] == "wired":
                conn = '<span class="text-xs" style="color:var(--sh-accent)">wired</span>'

            rows += f'''<tr>
                <td class="mono text-xs">{h(d["mac"])}</td>
                <td class="text-sm">{h(d["ip"] or "—")}</td>
                <td>{label_html}</td>
                <td class="text-xs">{icon} {h(d["device_type"] or "unknown")}</td>
                <td class="text-xs text-muted">{h(d["vendor"] or "—")}</td>
                <td>{conn}</td>
                <td class="text-xs text-muted">{_ago(d["last_seen"])}</td>
                <td>
                  <button class="sh-btn"
                    hx-get="/dashboard/partials/device-detail/{d["mac"]}"
                    hx-target="#device-detail"
                    hx-swap="innerHTML show:top"
                    onclick="document.getElementById('device-detail').style.display='block'">details</button>
                </td>
            </tr>'''

        return f'''<p class="text-xs text-muted mb-1">{len(device_data)} devices</p>
        <div style="max-height:calc(100vh - 280px);overflow-y:auto">
        <table class="sh-table">
            <tr><th>MAC</th><th>IP</th><th>Label</th><th>Type</th><th>Vendor</th><th>Conn</th><th>Last Seen</th><th></th></tr>
            {rows}
        </table></div>'''
    except Exception as exc:
        return f'<p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# HTMX Partials — device detail
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/device-detail/{mac}", response_class=HTMLResponse)
async def partial_device_detail(mac: str):
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Device, Event, Alert

        with session_scope() as session:
            device = session.query(Device).filter(Device.mac == mac).first()
            if not device:
                return '<p class="text-muted">Device not found.</p>'

            d = {
                "mac": device.mac, "ip": device.ip, "vendor": device.vendor,
                "device_type": device.device_type, "label": device.label,
                "os_family": device.os_family, "connection_type": device.connection_type,
                "network_role": device.network_role, "ap": device.ap,
                "hostnames": device.hostnames, "services": device.services,
                "device_notes": device.device_notes, "expected_behavior": device.expected_behavior,
                "first_seen": device.first_seen, "last_seen": device.last_seen,
                "updated_by": device.updated_by,
            }

            recent_events = (
                session.query(Event)
                .filter(Event.device_id == mac)
                .order_by(Event.ts.desc())
                .limit(15)
                .all()
            )
            events = [{
                "ts": e.ts, "event_type": e.event_type,
                "severity": e.severity, "message": e.message,
            } for e in recent_events]

            alert_count = session.query(Alert).filter(Alert.device_id == mac).count()

        # Device type options for the dropdown
        type_options = ["", "phone", "laptop", "desktop", "tablet", "server",
                       "router", "ap", "switch", "iot", "media", "printer", "camera", "unknown"]
        type_select = "".join(
            f'<option value="{t}" {"selected" if t == (d["device_type"] or "") else ""}>{t or "— unset —"}</option>'
            for t in type_options
        )

        # Network role dropdown options
        role_options = ["", "infrastructure", "client", "server", "iot"]
        role_select = "".join(
            f'<option value="{r}" {"selected" if r == (d["network_role"] or "") else ""}>{r or "— unset —"}</option>'
            for r in role_options
        )

        # Sanitise MAC for use in HTML ids (colons not allowed)
        mac_id = d["mac"].replace(":", "")

        # Build editable detail card
        html = f'''
        <div class="flex items-center gap-1" style="margin-bottom:0.75rem">
            <h2 style="margin:0">Device: {h(d["label"] or d["ip"] or d["mac"])}</h2>
            {f'<span class="badge badge-err">{alert_count} alerts</span>' if alert_count > 0 else ''}
            <button class="sh-btn" onclick="this.closest('.sh-card').style.display='none'" style="margin-left:auto">&times; close</button>
        </div>
        <div class="sh-grid" style="grid-template-columns:1fr 1fr">
            <div>
                <table class="sh-table">
                    <tr><td class="text-muted text-xs">MAC</td><td class="mono text-sm">{h(d["mac"])}</td></tr>
                    <tr><td class="text-muted text-xs">IP</td><td>{h(d["ip"] or "—")}</td></tr>
                    <tr><td class="text-muted text-xs">Vendor</td><td>{h(d["vendor"] or "—")}</td></tr>
                    <tr>
                        <td class="text-muted text-xs">Label</td>
                        <td x-data="{{editing: false, value: '{h(d["label"] or "").replace(chr(39), "&#39;")}' }}">
                            <span x-show="!editing" @click="editing=true" style="cursor:pointer" title="Click to edit">
                                {h(d["label"]) if d["label"] else '<span class="text-muted">Click to set...</span>'}
                            </span>
                            <form x-show="editing" @submit.prevent="editing=false"
                                  hx-post="/dashboard/actions/update-device/{d["mac"]}"
                                  hx-trigger="submit"
                                  hx-vals='{{"field": "label"}}'
                                  hx-swap="none"
                                  style="display:inline">
                                <input class="edit-input" name="value"
                                       :value="value" @keydown.escape="editing=false"
                                       @change="value=$el.value"
                                       placeholder="Give this device a name..."
                                       x-ref="labelInput" x-effect="if(editing) $nextTick(() => $refs.labelInput.focus())" />
                            </form>
                        </td>
                    </tr>
                    <tr>
                        <td class="text-muted text-xs">Type</td>
                        <td>
                            <select class="edit-select"
                                hx-post="/dashboard/actions/update-device/{d["mac"]}"
                                hx-trigger="change"
                                hx-vals='{{"field": "device_type"}}'
                                hx-swap="none"
                                name="value">
                                {type_select}
                            </select>
                        </td>
                    </tr>
                    <tr><td class="text-muted text-xs">OS</td><td>{h(d["os_family"] or "—")}</td></tr>
                    <tr>
                        <td class="text-muted text-xs">Role</td>
                        <td>
                            <select class="edit-select"
                                hx-post="/dashboard/actions/update-device/{d["mac"]}"
                                hx-trigger="change"
                                hx-vals='{{"field": "network_role"}}'
                                hx-swap="none"
                                name="value">
                                {role_select}
                            </select>
                        </td>
                    </tr>
                    <tr><td class="text-muted text-xs">Connection</td><td>{h(d["connection_type"] or "—")}{(" / AP: " + h(d["ap"])) if d["ap"] else ""}</td></tr>
                    <tr><td class="text-muted text-xs">First seen</td><td>{_ago(d["first_seen"])}</td></tr>
                    <tr><td class="text-muted text-xs">Last seen</td><td>{_ago(d["last_seen"])}</td></tr>
                    <tr><td class="text-muted text-xs">Updated by</td><td>{h(d["updated_by"] or "—")}</td></tr>
                </table>
            </div>
            <div>'''

        if d["hostnames"]:
            html += '<p class="text-xs text-muted" style="margin:0 0 0.3rem">Hostnames</p><ul style="margin:0;padding-left:1rem">'
            if isinstance(d["hostnames"], dict):
                for src, name in d["hostnames"].items():
                    html += f'<li class="text-sm">{h(str(name))} <span class="text-xs text-muted">({h(str(src))})</span></li>'
            elif isinstance(d["hostnames"], list):
                for name in d["hostnames"]:
                    html += f'<li class="text-sm">{h(str(name))}</li>'
            html += '</ul>'

        if d["services"]:
            html += '<p class="text-xs text-muted" style="margin:0.5rem 0 0.3rem">Services / Open Ports</p><ul style="margin:0;padding-left:1rem">'
            if isinstance(d["services"], dict):
                for port, info in d["services"].items():
                    svc_name = info.get("name", info.get("service", "")) if isinstance(info, dict) else str(info)
                    svc_desc = info.get("description", "") if isinstance(info, dict) else ""
                    port_id = f"svc-{mac_id}-{h(str(port))}"
                    html += f'''<li class="text-sm mono" style="margin-bottom:0.3rem">
                        {h(str(port))} — {h(svc_name)}
                        <span x-data="{{editing: false, desc: '{h(svc_desc).replace(chr(39), "&#39;")}'}}" style="margin-left:0.5rem">
                            <span x-show="!editing" @click="editing=true" class="text-xs" style="cursor:pointer;color:var(--sh-accent)" title="Click to edit description">
                                <template x-if="desc">
                                    <span x-text="desc" class="text-xs" style="font-family:inherit;color:var(--sh-text-muted)"></span>
                                </template>
                                <template x-if="!desc">
                                    <span class="text-muted">+ describe</span>
                                </template>
                            </span>
                            <form x-show="editing" @submit.prevent="editing=false" style="display:inline"
                                  hx-put="/api/v1/devices/{d["mac"]}/services/{port}"
                                  hx-headers='{{"Content-Type": "application/json"}}'
                                  hx-vals='js:JSON.stringify({{description: document.getElementById("{port_id}").value}})'
                                  hx-swap="none">
                                <input id="{port_id}" class="edit-input text-xs" style="width:160px"
                                       :value="desc" @keydown.escape="editing=false"
                                       @change="desc=$el.value"
                                       placeholder="Service description..."
                                       x-ref="descInput" x-effect="if(editing) $nextTick(() => $refs.descInput.focus())" />
                            </form>
                        </span>
                    </li>'''
            elif isinstance(d["services"], list):
                for svc in d["services"]:
                    html += f'<li class="text-sm mono">{h(str(svc))}</li>'
            html += '</ul>'

        # Notes section — timeline + add form
        html += f'''
        <p class="text-xs text-muted" style="margin:0.75rem 0 0.3rem">Notes</p>
        <div id="notes-{mac_id}"
             hx-get="/dashboard/partials/device-notes/{d["mac"]}"
             hx-trigger="load"
             hx-swap="innerHTML">
            <span class="text-xs text-muted">Loading notes...</span>
        </div>
        <form style="margin-top:0.5rem"
              hx-post="/dashboard/actions/add-device-note/{d["mac"]}"
              hx-swap="none"
              hx-on::after-request="document.getElementById('note-input-{mac_id}').value=''; htmx.ajax('GET', '/dashboard/partials/device-notes/{d["mac"]}', '#notes-{mac_id}')">
            <textarea id="note-input-{mac_id}" class="edit-textarea" name="text" placeholder="Add a note about this device..." rows="2"></textarea>
            <button class="sh-btn sh-btn-ok" type="submit" style="margin-top:0.3rem">Save Note</button>
        </form>
        '''

        html += '</div></div>'

        # Activity timeline chart
        chart_id = f"dev-chart-{d['mac'].replace(':', '')}"
        html += f'''
        <h2 style="margin-top:1rem">Activity Timeline (24h)</h2>
        <div style="height:150px;position:relative;margin-bottom:0.75rem">
            <canvas id="{chart_id}"></canvas>
        </div>
        <div hx-get="/dashboard/partials/device-timeline-data/{d["mac"]}"
             hx-trigger="load"
             hx-swap="none"
             hx-on::after-request="renderDevChart('{chart_id}', event)"></div>
        <script>
        function renderDevChart(canvasId, evt) {{
            try {{
                const data = JSON.parse(evt.detail.xhr.responseText);
                const ctx = document.getElementById(canvasId);
                if (!ctx) return;
                new Chart(ctx, {{
                    type: 'bar',
                    data: {{
                        labels: data.labels || [],
                        datasets: [
                            {{ label: 'Events', data: data.events || [], backgroundColor: 'rgba(88,166,255,0.6)', borderRadius: 2 }},
                            {{ label: 'Alerts', data: data.alerts || [], backgroundColor: 'rgba(248,81,73,0.5)', borderRadius: 2 }},
                        ]
                    }},
                    options: {{
                        responsive: true, maintainAspectRatio: false,
                        plugins: {{ legend: {{ position: 'top', labels: {{ color: '#8b949e', boxWidth: 10, font: {{ size: 10 }} }} }} }},
                        scales: {{
                            x: {{ ticks: {{ color: '#8b949e', font: {{ size: 9 }}, maxRotation: 0 }}, grid: {{ color: '#21262d' }} }},
                            y: {{ beginAtZero: true, ticks: {{ color: '#8b949e', font: {{ size: 9 }} }}, grid: {{ color: '#21262d' }} }},
                        }},
                    }},
                }});
            }} catch(e) {{ console.debug('dev chart error:', e); }}
        }}
        </script>
        '''

        # Recent events
        if events:
            html += f'<h2 style="margin-top:1rem">Recent Events <span class="text-xs text-muted">{len(events)} shown</span></h2><table class="sh-table"><tr><th>Time</th><th>Type</th><th>Sev</th><th>Message</th></tr>'
            for ev in events:
                sev_cls = f"sev-{ev['severity']}" if ev['severity'] else "sev-info"
                html += f'<tr><td class="text-xs text-muted nowrap">{_fmt_ts(ev["ts"])}</td><td class="text-xs">{h(ev["event_type"])}</td><td class="{sev_cls} text-xs">{h(ev["severity"] or "")}</td><td class="text-sm">{h((ev["message"] or "—")[:150])}</td></tr>'
            html += '</table>'
        else:
            html += '<p class="text-xs text-muted" style="margin-top:0.75rem">No recent events for this device.</p>'

        return html
    except Exception as exc:
        return f'<p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# HTMX Partials — device notes
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/device-notes/{mac}", response_class=HTMLResponse)
async def partial_device_notes(mac: str):
    """Render notes timeline for a device."""
    try:
        return _render_notes("device", mac)
    except Exception as exc:
        return f'<p class="text-muted text-sm">Error: {h(str(exc))}</p>'


# ---------------------------------------------------------------------------
# HTMX Partials — rule notes
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/rule-notes/{rule_name}", response_class=HTMLResponse)
async def partial_rule_notes(rule_name: str):
    """Render notes timeline for a rule."""
    try:
        return _render_notes("rule", rule_name)
    except Exception as exc:
        return f'<p class="text-muted text-sm">Error: {h(str(exc))}</p>'


@router.post("/dashboard/actions/add-rule-note/{rule_name}", response_class=HTMLResponse)
async def action_add_rule_note(rule_name: str, text: str = Form("")):
    """Add a note to a rule (form-encoded from dashboard)."""
    if not text.strip():
        return HTMLResponse(status_code=204)
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Rule, Note

        with session_scope() as session:
            rule = session.query(Rule).filter(Rule.name == rule_name).first()
            if not rule:
                return HTMLResponse('<span class="text-xs text-muted">rule not found</span>', status_code=404)
            session.add(Note(
                entity_type="rule",
                entity_id=rule_name,
                text=text.strip(),
                source="user",
            ))

        return HTMLResponse(status_code=204)
    except Exception as exc:
        return HTMLResponse(f'<span class="text-xs sev-high">Error: {h(str(exc))}</span>', status_code=500)


# ---------------------------------------------------------------------------
# HTMX Partials — finding notes
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/finding-notes/{finding_id}", response_class=HTMLResponse)
async def partial_finding_notes(finding_id: int):
    """Render notes timeline for a finding."""
    try:
        return _render_notes("finding", str(finding_id))
    except Exception as exc:
        return f'<p class="text-muted text-sm">Error: {h(str(exc))}</p>'


@router.post("/dashboard/actions/add-finding-note/{finding_id}", response_class=HTMLResponse)
async def action_add_finding_note(finding_id: int, text: str = Form("")):
    """Add a note to a finding (form-encoded from dashboard)."""
    if not text.strip():
        return HTMLResponse(status_code=204)
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Finding, Note

        with session_scope() as session:
            finding = session.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                return HTMLResponse('<span class="text-xs text-muted">finding not found</span>', status_code=404)
            session.add(Note(
                entity_type="finding",
                entity_id=str(finding_id),
                text=text.strip(),
                source="user",
            ))

        return HTMLResponse(status_code=204)
    except Exception as exc:
        return HTMLResponse(f'<span class="text-xs sev-high">Error: {h(str(exc))}</span>', status_code=500)


# ---------------------------------------------------------------------------
# Device timeline data — hourly event/alert counts for a specific device
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/device-timeline-data/{mac}")
async def device_timeline_data(mac: str):
    """Return 24h hourly event + alert counts for a device as JSON."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Event, Alert
        from sqlalchemy import func

        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)

        # Build hour buckets
        hours = []
        for i in range(24):
            h_start = start + timedelta(hours=i)
            hours.append(h_start)

        labels = [h.strftime("%H:00") for h in hours]
        ev_counts = [0] * 24
        al_counts = [0] * 24

        with session_scope() as session:
            # Events per hour
            events = (
                session.query(Event.ts)
                .filter(Event.device_id == mac, Event.ts >= start)
                .all()
            )
            for (ts,) in events:
                if ts and ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts:
                    idx = int((ts - start).total_seconds() // 3600)
                    if 0 <= idx < 24:
                        ev_counts[idx] += 1

            # Alerts per hour
            alerts = (
                session.query(Alert.ts)
                .filter(Alert.device_id == mac, Alert.ts >= start)
                .all()
            )
            for (ts,) in alerts:
                if ts and ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts:
                    idx = int((ts - start).total_seconds() // 3600)
                    if 0 <= idx < 24:
                        al_counts[idx] += 1

        return JSONResponse({"labels": labels, "events": ev_counts, "alerts": al_counts})
    except Exception as exc:
        return JSONResponse({"labels": [], "events": [], "alerts": [], "error": str(exc)})


# ---------------------------------------------------------------------------
# HTMX Partials — alerts table (full page)
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/alerts-table", response_class=HTMLResponse)
async def partial_alerts_table():
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Alert, Device, Rule

        with session_scope() as session:
            alerts = (
                session.query(Alert)
                .order_by(Alert.ts.desc())
                .limit(500)
                .all()
            )

            # Build device lookup for display names
            device_macs = {a.device_id for a in alerts if a.device_id}
            devices = {}
            if device_macs:
                for d in session.query(Device).filter(Device.mac.in_(device_macs)).all():
                    name_parts = []
                    if d.label:
                        name_parts.append(d.label)
                    elif d.vendor:
                        name_parts.append(d.vendor)
                    if d.ip:
                        name_parts.append(f"({d.ip})")
                    devices[d.mac] = {
                        "name": " ".join(name_parts) if name_parts else d.mac,
                        "ip": d.ip, "vendor": d.vendor, "label": d.label,
                        "device_type": d.device_type, "mac": d.mac,
                    }

            # Build rule lookup for descriptions
            rule_names = {a.rule_name for a in alerts if a.rule_name}
            rule_descs = {}
            if rule_names:
                for r in session.query(Rule).filter(Rule.name.in_(rule_names)).all():
                    rule_descs[r.name] = r.description or ""

            alert_data = [{
                "id": a.id, "ts": a.ts, "rule_name": a.rule_name,
                "severity": a.severity, "message": a.message,
                "device_id": a.device_id, "sent": a.sent,
                "rule_id": a.rule_id,
                "device_display": devices.get(a.device_id, {}).get("name", a.device_id or "—"),
                "device_info": devices.get(a.device_id, {}),
                "rule_desc": rule_descs.get(a.rule_name, ""),
            } for a in alerts]

        if not alert_data:
            return '<p class="text-muted text-sm">No alerts yet. Rules with action "alert" will appear here when they fire.</p>'

        unacked = sum(1 for a in alert_data if not a["sent"])
        rows = ""
        for i, a in enumerate(alert_data):
            sev_cls = f"sev-{a['severity']}" if a['severity'] else "sev-info"
            ack_cls = ' style="opacity:0.5"' if a['sent'] else ""
            ack_badge = '<span class="badge badge-info">ack</span>' if a['sent'] else ''
            row_id = f"alert-{a['id']}"

            rows += f'''<tr class="expand-row" onclick="document.getElementById('{row_id}').classList.toggle('open')"{ack_cls}>
                <td class="nowrap text-xs text-muted">{_fmt_ts(a["ts"])}</td>
                <td><span class="{sev_cls}">{a["severity"] or "?"}</span></td>
                <td class="text-xs">{h(a["rule_name"])}</td>
                <td class="text-sm">{h(a["device_display"])}</td>
                <td class="text-sm">{h((a["message"] or "—")[:120])}</td>
                <td class="nowrap" onclick="event.stopPropagation()">{ack_badge}
                  {f'<button class="sh-btn sh-btn-ok" hx-post="/dashboard/actions/ack-alert/{a["id"]}" hx-swap="outerHTML">ack</button>' if not a["sent"] else ''}
                  <button class="sh-btn sh-btn-warn" hx-post="/dashboard/actions/dismiss-alert/{a["id"]}" hx-swap="outerHTML" title="False positive — noise">dismiss</button>
                </td>
            </tr>'''

            # Expandable detail row
            di = a["device_info"]
            detail_parts = []
            if a["rule_desc"]:
                detail_parts.append(f'<dt>Rule</dt><dd>{h(a["rule_desc"])}</dd>')
            detail_parts.append(f'<dt>Message</dt><dd>{h(a["message"] or "—")}</dd>')
            if di:
                if di.get("mac"):
                    detail_parts.append(f'<dt>Device MAC</dt><dd class="mono">{h(di["mac"])}</dd>')
                if di.get("ip"):
                    detail_parts.append(f'<dt>Device IP</dt><dd>{h(di["ip"])}</dd>')
                if di.get("vendor"):
                    detail_parts.append(f'<dt>Vendor</dt><dd>{h(di["vendor"])}</dd>')
                if di.get("device_type"):
                    detail_parts.append(f'<dt>Type</dt><dd>{h(di["device_type"])}</dd>')
            detail_parts.append(f'<dt>Time</dt><dd>{a["ts"].strftime("%Y-%m-%d %H:%M:%S") if a["ts"] else "—"}</dd>')

            rows += f'''<tr id="{row_id}" class="expand-detail">
                <td colspan="6"><dl class="detail-grid">{"".join(detail_parts)}</dl></td>
            </tr>'''

        return f'''<p class="text-xs text-muted mb-1">{unacked} unacknowledged of {len(alert_data)} total — click a row to expand</p>
        <div style="max-height:calc(100vh - 340px);overflow-y:auto">
        <table class="sh-table">
            <tr><th>Time</th><th>Sev</th><th>Rule</th><th>Device</th><th>Message</th><th></th></tr>
            {rows}
        </table></div>'''
    except Exception as exc:
        return f'<p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# HTMX Partials — alerts grouped
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/alerts-grouped", response_class=HTMLResponse)
async def partial_alerts_grouped():
    """Alerts grouped by rule+device with count badges."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Alert, Device, Rule
        from sqlalchemy import func

        with session_scope() as session:
            grouped = (
                session.query(
                    Alert.rule_name,
                    Alert.device_id,
                    func.max(Alert.severity).label("severity"),
                    func.max(Alert.ts).label("latest_ts"),
                    func.min(Alert.ts).label("first_ts"),
                    func.count(Alert.id).label("cnt"),
                    func.max(Alert.message).label("message"),
                    func.sum(Alert.sent).label("acked_count"),
                )
                .group_by(Alert.rule_name, Alert.device_id)
                .order_by(func.max(Alert.ts).desc())
                .limit(50)
                .all()
            )

            # Resolve device names
            device_macs = {g.device_id for g in grouped if g.device_id}
            dev_names = {}
            if device_macs:
                for d in session.query(Device).filter(Device.mac.in_(device_macs)).all():
                    name = d.label or d.vendor or d.mac[:8]
                    if d.ip:
                        name += f" ({d.ip})"
                    dev_names[d.mac] = name

            # Rule descriptions
            rule_names = {g.rule_name for g in grouped if g.rule_name}
            rule_descs = {}
            if rule_names:
                for r in session.query(Rule).filter(Rule.name.in_(rule_names)).all():
                    rule_descs[r.name] = r.description or ""

            data = [{
                "rule_name": g.rule_name, "device_id": g.device_id,
                "severity": g.severity, "latest_ts": g.latest_ts,
                "first_ts": g.first_ts, "count": g.cnt,
                "message": g.message,
                "acked_count": g.acked_count or 0,
                "device_name": dev_names.get(g.device_id, g.device_id or "—"),
                "rule_desc": rule_descs.get(g.rule_name, ""),
            } for g in grouped]

        if not data:
            return '<p class="text-muted text-sm">No alerts yet.</p>'

        total = sum(d["count"] for d in data)
        rows = ""
        for i, d in enumerate(data):
            sev_cls = f"sev-{d['severity']}" if d['severity'] else "sev-info"
            count_badge = f'<span class="badge badge-info">&times;{d["count"]}</span>' if d["count"] > 1 else ""
            ack_str = f'{d["acked_count"]}/{d["count"]} acked' if d["acked_count"] else ""
            # Stable ID from rule+device so expand state survives refresh
            row_key = f"{d['rule_name']}_{d['device_id'] or 'none'}"
            row_id = f"agrp-{hash(row_key) & 0xFFFFFFFF:08x}"

            rows += f'''<tr class="expand-row" onclick="document.getElementById('{row_id}').classList.toggle('open')">
                <td class="nowrap text-xs text-muted">{_fmt_ts(d["latest_ts"])}</td>
                <td><span class="{sev_cls}">{d["severity"] or "?"}</span></td>
                <td class="text-xs">{h(d["rule_name"])} {count_badge}</td>
                <td class="text-xs">{h(d["device_name"])}</td>
                <td class="text-sm">{h((d["message"] or "—")[:120])}</td>
            </tr>'''

            detail_parts = []
            if d["rule_desc"]:
                detail_parts.append(f'<dt>Rule</dt><dd>{h(d["rule_desc"])}</dd>')
            detail_parts.append(f'<dt>Occurrences</dt><dd>{d["count"]} total, {d["acked_count"]} acknowledged</dd>')
            detail_parts.append(f'<dt>First seen</dt><dd>{d["first_ts"].strftime("%Y-%m-%d %H:%M:%S") if d["first_ts"] else "—"}</dd>')
            detail_parts.append(f'<dt>Last seen</dt><dd>{d["latest_ts"].strftime("%Y-%m-%d %H:%M:%S") if d["latest_ts"] else "—"}</dd>')
            detail_parts.append(f'<dt>Message</dt><dd>{h(d["message"] or "—")}</dd>')

            rows += f'''<tr id="{row_id}" class="expand-detail">
                <td colspan="5"><dl class="detail-grid">{"".join(detail_parts)}</dl></td>
            </tr>'''

        return f'''<p class="text-xs text-muted mb-1">{len(data)} groups, {total} total alerts — click a row to expand</p>
        <div style="max-height:calc(100vh - 340px);overflow-y:auto">
        <table class="sh-table">
            <tr><th>Last</th><th>Sev</th><th>Rule</th><th>Device</th><th>Message</th></tr>
            {rows}
        </table></div>'''
    except Exception as exc:
        return f'<p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# HTMX Partials — findings table
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/findings-table", response_class=HTMLResponse)
async def partial_findings_table():
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Finding

        with session_scope() as session:
            findings = (
                session.query(Finding)
                .filter(Finding.dismissed == False)
                .order_by(Finding.ts.desc())
                .limit(50)
                .all()
            )
            finding_data = [{
                "id": f.id, "ts": f.ts, "rule_name": f.rule_name,
                "severity": f.severity, "summary": f.summary,
                "confidence": f.confidence, "device_id": f.device_id,
                "source": f.source,
            } for f in findings]

        if not finding_data:
            return '<p class="text-muted text-sm">No findings yet. Agent analysis results will appear here.</p>'

        rows = ""
        for f in finding_data:
            sev_cls = f"sev-{f['severity']}" if f['severity'] else "sev-info"
            row_id = f"finding-{f['id']}"
            notes_id = f"finding-notes-{f['id']}"
            note_input_id = f"finding-note-input-{f['id']}"

            rows += f'''<tr class="expand-row" onclick="document.getElementById('{row_id}').classList.toggle('open')">
                <td class="nowrap text-xs text-muted">{_fmt_ts(f["ts"])}</td>
                <td><span class="{sev_cls}">{f["severity"]}</span></td>
                <td class="text-xs">{f["rule_name"] or "—"}</td>
                <td class="text-xs text-muted">{f["source"]}</td>
                <td class="text-sm">{(f["summary"] or "—")[:120]}</td>
                <td class="text-xs">{f["confidence"]}</td>
            </tr>'''

            # Expandable detail row with full summary + notes
            device_str = f' &middot; Device: <span class="mono text-xs">{h(f["device_id"])}</span>' if f["device_id"] else ""
            rows += f'''<tr id="{row_id}" class="expand-detail">
                <td colspan="6">
                    <dl class="detail-grid">
                        <dt>Full Summary</dt><dd class="text-sm">{h(f["summary"] or "—")}</dd>
                        <dt>Details</dt><dd class="text-xs">Rule: {h(f["rule_name"] or "—")} &middot; Confidence: {f["confidence"]}{device_str}</dd>
                    </dl>
                    <p class="text-xs text-muted" style="margin:0.75rem 0 0.3rem">Notes</p>
                    <div id="{notes_id}"
                         hx-get="/dashboard/partials/finding-notes/{f['id']}"
                         hx-trigger="intersect once"
                         hx-swap="innerHTML">
                        <span class="text-xs text-muted">Loading notes...</span>
                    </div>
                    <form style="margin-top:0.5rem" onclick="event.stopPropagation()"
                          hx-post="/dashboard/actions/add-finding-note/{f['id']}"
                          hx-swap="none"
                          hx-on::after-request="document.getElementById('{note_input_id}').value=''; htmx.ajax('GET', '/dashboard/partials/finding-notes/{f['id']}', '#{notes_id}')">
                        <textarea id="{note_input_id}" class="edit-textarea" name="text" placeholder="Add a note about this finding..." rows="2" onclick="event.stopPropagation()"></textarea>
                        <button class="sh-btn sh-btn-ok" type="submit" style="margin-top:0.3rem">Save Note</button>
                    </form>
                </td>
            </tr>'''

        return f'''<p class="text-xs text-muted mb-1">{len(finding_data)} findings — click a row to expand</p>
        <table class="sh-table">
            <tr><th>Time</th><th>Sev</th><th>Rule</th><th>Source</th><th>Summary</th><th>Conf</th></tr>
            {rows}
        </table>'''
    except Exception as exc:
        return f'<p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# Alert actions
# ---------------------------------------------------------------------------

@router.post("/dashboard/actions/ack-alert/{alert_id}", response_class=HTMLResponse)
async def action_ack_alert(alert_id: int):
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Alert

        with session_scope() as session:
            alert = session.query(Alert).filter(Alert.id == alert_id).first()
            if alert:
                alert.sent = True
                alert.sent_at = datetime.now(timezone.utc)
        return '<span class="badge badge-info">ack</span>'
    except Exception:
        return '<span class="text-xs sev-high">error</span>'


@router.post("/dashboard/actions/dismiss-alert/{alert_id}", response_class=HTMLResponse)
async def action_dismiss_alert(alert_id: int):
    """Dismiss an alert as false positive — decrements rule trust.

    This is the primary feedback mechanism for the critic cycle.
    Alerts always have rule_id, so this reliably updates the rule.
    """
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Alert, Rule

        with session_scope() as session:
            alert = session.query(Alert).filter(Alert.id == alert_id).first()
            if not alert:
                return '<span class="text-xs text-muted">not found</span>'

            # Mark as acknowledged + dismissed
            alert.sent = True
            alert.sent_at = datetime.now(timezone.utc)

            # Feedback: dismiss = false positive for the rule
            if alert.rule_id:
                rule = session.query(Rule).filter(Rule.id == alert.rule_id).first()
                if rule:
                    rule.false_positive_count = (rule.false_positive_count or 0) + 1

        return '<span class="badge badge-info">dismissed</span>'
    except Exception:
        return '<span class="text-xs sev-high">error</span>'


@router.post("/dashboard/actions/ack-all-alerts", response_class=HTMLResponse)
async def action_ack_all_alerts():
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Alert
        now = datetime.now(timezone.utc)

        with session_scope() as session:
            unacked = session.query(Alert).filter(Alert.sent == False).all()
            for a in unacked:
                a.sent = True
                a.sent_at = now
            count = len(unacked)

        return f'<p class="text-sm" style="color:var(--sh-green)">Acknowledged {count} alert(s).</p>'
    except Exception as exc:
        return f'<p class="text-sm sev-high">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# HTMX Partials — WAN stats
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/wan-stats", response_class=HTMLResponse)
async def partial_wan_stats():
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import EventRollup
        from sqlalchemy import func

        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(hours=24)

        with session_scope() as session:
            wan_1h = session.query(func.coalesce(func.sum(EventRollup.count), 0)).filter(
                EventRollup.hour >= hour_ago, EventRollup.event_type == "fw_wan_block"
            ).scalar() or 0

            wan_24h = session.query(func.coalesce(func.sum(EventRollup.count), 0)).filter(
                EventRollup.hour >= day_ago, EventRollup.event_type == "fw_wan_block"
            ).scalar() or 0

            # Unique sources and top port from rollup metadata
            rollups = session.query(EventRollup).filter(
                EventRollup.hour >= day_ago, EventRollup.event_type == "fw_wan_block"
            ).all()

            unique_sources = set()
            port_counts: dict[str, int] = {}
            for r in rollups:
                extra = r.extra or {}
                unique_sources.update(extra.get("unique_sources", []))
                for port, cnt in extra.get("top_ports", {}).items():
                    port_counts[port] = port_counts.get(port, 0) + cnt

        top_port = max(port_counts, key=port_counts.get) if port_counts else "—"

        # Add in-memory counters
        try:
            from sentinel_home.metrics.counters import get_counters
            snap = get_counters().get_detailed_snapshot()
            for key, bucket in snap.items():
                if "fw_wan_block" in key:
                    wan_1h += bucket["count"]
                    unique_sources.update(bucket["unique_sources"])
        except Exception:
            pass

        return f'''
        <div class="sh-grid" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr))">
          <div class="sh-card sh-stat">
            <div class="value" style="color:var(--sh-red)">{wan_1h:,}</div>
            <div class="label">Blocks (1h)</div>
          </div>
          <div class="sh-card sh-stat">
            <div class="value" style="color:var(--sh-orange)">{wan_24h:,}</div>
            <div class="label">Blocks (24h)</div>
          </div>
          <div class="sh-card sh-stat">
            <div class="value" style="color:var(--sh-accent)">{len(unique_sources):,}</div>
            <div class="label">Unique Sources (24h)</div>
          </div>
          <div class="sh-card sh-stat">
            <div class="value" style="color:var(--sh-purple)">{top_port}</div>
            <div class="label">Top Port</div>
          </div>
        </div>'''
    except Exception as exc:
        return f'<div class="sh-card"><p class="text-muted text-sm">Error: {exc}</p></div>'


@router.get("/dashboard/partials/wan-chart-data")
async def partial_wan_chart_data():
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import EventRollup
        from sqlalchemy import func

        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(hours=24)
        labels = []
        counts = []

        with session_scope() as session:
            for i in range(24):
                h_start = day_ago + timedelta(hours=i)
                h_end = h_start + timedelta(hours=1)
                labels.append(h_start.strftime("%H:%M"))

                wc = session.query(func.coalesce(func.sum(EventRollup.count), 0)).filter(
                    EventRollup.hour >= h_start, EventRollup.hour < h_end,
                    EventRollup.event_type == "fw_wan_block",
                ).scalar() or 0
                counts.append(wc)

        return {"labels": labels, "counts": counts}
    except Exception:
        return {"labels": [], "counts": []}


@router.get("/dashboard/partials/wan-top-sources", response_class=HTMLResponse)
async def partial_wan_top_sources():
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import EventRollup

        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(hours=24)

        with session_scope() as session:
            rollups = session.query(EventRollup).filter(
                EventRollup.hour >= day_ago, EventRollup.event_type == "fw_wan_block"
            ).all()

            source_counts: dict[str, int] = {}
            for r in rollups:
                extra = r.extra or {}
                # Prefer top_sources (IP→count) from new rollups
                ts = extra.get("top_sources", {})
                if ts:
                    for src, cnt in ts.items():
                        source_counts[src] = source_counts.get(src, 0) + cnt
                else:
                    # Fallback for old rollups that only have sample_sources
                    for src in extra.get("sample_sources", []):
                        source_counts[src] = source_counts.get(src, 0) + 1

        # Also include current-hour in-memory data
        try:
            from sentinel_home.metrics.counters import get_counters
            snapshot = get_counters().get_detailed_snapshot()
            for key, data in snapshot.items():
                if "fw_wan_block" in key:
                    for src in data.get("unique_sources", set()):
                        source_counts[src] = source_counts.get(src, 0) + 1
        except Exception:
            pass

        if not source_counts:
            return '<h2>Top Blocked Sources</h2><p class="text-muted text-sm">No WAN block data yet.</p>'

        sorted_sources = sorted(source_counts.items(), key=lambda x: -x[1])[:20]
        rows = ""
        for src, cnt in sorted_sources:
            rows += f'<tr><td class="mono text-sm">{h(src)}</td><td>{cnt:,}</td></tr>'

        return f'''<h2>Top Blocked Sources <span class="text-xs text-muted">(24h)</span></h2>
        <div style="max-height:400px;overflow-y:auto">
        <table class="sh-table">
            <tr><th>Source IP</th><th>Blocked</th></tr>
            {rows}
        </table></div>'''
    except Exception as exc:
        return f'<h2>Top Blocked Sources</h2><p class="text-muted text-sm">Error: {exc}</p>'


@router.get("/dashboard/partials/wan-heatmap", response_class=HTMLResponse)
async def partial_wan_heatmap():
    """Render a 7-day × 24-hour block heatmap as a CSS grid."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import EventRollup

        now = datetime.now(timezone.utc)
        week_ago = now - timedelta(days=7)

        # Build 7×24 grid: grid[day_index][hour] = count
        # day_index 0 = oldest day, 6 = today
        grid: list[list[int]] = [[0] * 24 for _ in range(7)]
        day_labels: list[str] = []

        base_day = (now - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
        for d in range(7):
            day = base_day + timedelta(days=d)
            day_labels.append(day.strftime("%a %-d"))

        with session_scope() as session:
            rollups = session.query(EventRollup).filter(
                EventRollup.hour >= week_ago,
                EventRollup.event_type == "fw_wan_block",
            ).all()

            for r in rollups:
                r_hour = r.hour
                if r_hour.tzinfo is None:
                    from datetime import timezone as _tz
                    r_hour = r_hour.replace(tzinfo=_tz.utc)
                day_offset = (r_hour.date() - base_day.date()).days
                if 0 <= day_offset < 7:
                    grid[day_offset][r_hour.hour] += r.count

        max_val = max((grid[d][h] for d in range(7) for h in range(24)), default=1) or 1

        def cell_color(count: int) -> str:
            if count == 0:
                return "#161b22"
            intensity = count / max_val
            # Scale from dim red to bright red
            r_val = int(80 + intensity * 168)
            g_val = int(20 + intensity * 20)
            b_val = int(20 + intensity * 20)
            return f"rgb({r_val},{g_val},{b_val})"

        # Build CSS grid: rows = days, columns = hours
        hour_headers = ''.join(
            f'<div style="font-size:0.6rem;color:#8b949e;text-align:center">'
            f'{"" if h % 3 != 0 else str(h)}</div>'
            for h in range(24)
        )

        rows_html = ""
        for d in range(7):
            label = day_labels[d]
            rows_html += f'<div style="font-size:0.7rem;color:#8b949e;line-height:1;padding-right:0.3rem;white-space:nowrap;display:flex;align-items:center">{h(label)}</div>'
            for hr in range(24):
                count = grid[d][hr]
                color = cell_color(count)
                title = f"{label} {hr:02d}:00 — {count:,} blocks"
                rows_html += (
                    f'<div title="{h(title)}" style="background:{color};border-radius:2px;'
                    f'width:100%;aspect-ratio:1;min-width:0"></div>'
                )

        return f'''<h2>Block Heatmap <span class="text-xs text-muted">(7d × 24h)</span></h2>
        <div style="overflow-x:auto">
          <div style="display:grid;grid-template-columns:40px repeat(24,1fr);gap:2px;min-width:480px">
            <div></div>
            {hour_headers}
            {rows_html}
          </div>
          <div style="margin-top:0.5rem;display:flex;align-items:center;gap:0.5rem;font-size:0.7rem;color:#8b949e">
            <span>low</span>
            <div style="display:flex;gap:2px">
              {''.join(f'<div style="width:12px;height:12px;border-radius:2px;background:{cell_color(int(max_val * i / 5))}"></div>' for i in range(6))}
            </div>
            <span>high ({max_val:,} max/hr)</span>
          </div>
        </div>'''
    except Exception as exc:
        return f'<h2>Block Heatmap</h2><p class="text-muted text-sm">Error: {exc}</p>'


@router.get("/dashboard/partials/wan-top-ports", response_class=HTMLResponse)
async def partial_wan_top_ports():
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import EventRollup

        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(hours=24)

        with session_scope() as session:
            rollups = session.query(EventRollup).filter(
                EventRollup.hour >= day_ago, EventRollup.event_type == "fw_wan_block"
            ).all()

            port_counts: dict[str, int] = {}
            for r in rollups:
                extra = r.extra or {}
                for port, cnt in extra.get("top_ports", {}).items():
                    port_counts[port] = port_counts.get(port, 0) + cnt

        if not port_counts:
            return '<h2>Top Targeted Ports</h2><p class="text-muted text-sm">No WAN block data yet.</p>'

        well_known = {
            "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS", "80": "HTTP",
            "443": "HTTPS", "445": "SMB", "3389": "RDP", "8080": "HTTP-Alt",
            "8443": "HTTPS-Alt", "5060": "SIP", "1433": "MSSQL", "3306": "MySQL",
        }

        sorted_ports = sorted(port_counts.items(), key=lambda x: -x[1])[:15]
        rows = ""
        for port, cnt in sorted_ports:
            svc = well_known.get(port, "")
            rows += f'<tr><td class="mono text-sm">{port}</td><td class="text-xs text-muted">{svc}</td><td>{cnt:,}</td></tr>'

        return f'''<h2>Top Targeted Ports <span class="text-xs text-muted">(24h)</span></h2>
        <table class="sh-table">
            <tr><th>Port</th><th>Service</th><th>Count</th></tr>
            {rows}
        </table>'''
    except Exception as exc:
        return f'<h2>Top Targeted Ports</h2><p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# HTMX Partials — settings
# ---------------------------------------------------------------------------

def _setting_input(section: str, key: str, value, input_type: str = "text", placeholder: str = "", options: list | None = None) -> str:
    """Generate an inline-editable setting field.

    Saves on change (blur) for selects/checkboxes, and after 500ms of
    inactivity for text/number inputs so the save fires before navigation.
    """
    # IDs must not contain dots — CSS selectors treat dots as class selectors
    target_id = f"save-{section.replace('.', '-')}-{key}"

    if input_type in ("text", "number"):
        # For text/number: save on both change (blur) and after typing stops.
        # This prevents navigation from cancelling unsaved changes.
        trigger = "change, keyup changed delay:500ms"
    else:
        trigger = "change"

    common = f'''hx-post="/dashboard/actions/save-setting"
        hx-vals='{{"section": "{section}", "key": "{key}"}}'
        hx-trigger="{trigger}"
        hx-target="#{target_id}"
        hx-swap="innerHTML"
        name="value"'''

    if options:
        opts = "".join(f'<option value="{o}" {"selected" if str(o) == str(value) else ""}>{o}</option>' for o in options)
        return f'<select class="edit-select" {common}>{opts}</select><span id="{target_id}"></span>'
    elif input_type == "checkbox":
        checked = "checked" if value else ""
        # Checkboxes: update hidden input value, then dispatch change for HTMX
        return f'''<label style="cursor:pointer"><input type="checkbox" {checked}
            onchange="var h=this.nextElementSibling; h.value=this.checked; h.dispatchEvent(new Event('change'))"
            style="margin-right:0.3rem" /><input type="hidden" value="{str(value).lower()}" {common} />
            </label><span id="{target_id}"></span>'''
    else:
        return f'<input class="edit-input" type="{input_type}" value="{h(str(value or ""))}" placeholder="{placeholder}" {common} /><span id="{target_id}"></span>'


@router.get("/dashboard/partials/settings-system", response_class=HTMLResponse)
async def partial_settings_system():
    try:
        from sentinel_home.config import get_settings
        settings = get_settings()

        log_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        log_select = _setting_input("server", "log_level", settings.server.log_level, options=log_levels)

        return f'''<h2>System</h2>
        <table class="sh-table">
            <tr><td class="text-muted text-xs">Version</td><td>1.0.0-dev</td></tr>
            <tr><td class="text-muted text-xs">Host</td><td>{settings.server.host}:{settings.server.port}</td></tr>
            <tr><td class="text-muted text-xs">Database</td><td class="mono text-xs">{settings.server.db_path}</td></tr>
            <tr><td class="text-muted text-xs">Log Level</td><td>{log_select}</td></tr>
            <tr><td class="text-muted text-xs">LAN CIDR</td><td>{settings.network.lan_cidr}</td></tr>
            <tr><td class="text-muted text-xs">Sniff Interface</td><td>{settings.network.sniff_interface}</td></tr>
            <tr><td class="text-muted text-xs">Syslog Mode</td><td>{settings.syslog.mode} (port {settings.syslog.udp_port})</td></tr>
            <tr><td class="text-muted text-xs">Agent</td><td>{"enabled (" + settings.agent.provider + ")" if settings.agent.enabled else "disabled"}</td></tr>
        </table>'''
    except Exception as exc:
        return f'<h2>System</h2><p class="text-muted text-sm">Error: {exc}</p>'


@router.get("/dashboard/partials/settings-collectors", response_class=HTMLResponse)
async def partial_settings_collectors():
    try:
        from sentinel_home.config import get_settings
        settings = get_settings()

        pihole_toggle = _setting_input("pihole", "enabled", settings.pihole.enabled, input_type="checkbox")
        pihole_host = _setting_input("pihole", "host", settings.pihole.host, placeholder="192.168.1.x")
        unifi_toggle = _setting_input("unifi", "enabled", settings.unifi.enabled, input_type="checkbox")
        unifi_host = _setting_input("unifi", "host", settings.unifi.host, placeholder="192.168.1.1")
        unifi_poll = _setting_input("unifi", "poll_interval_seconds", settings.unifi.poll_interval_seconds, input_type="number")
        plex_toggle = _setting_input("plex", "enabled", settings.plex.enabled, input_type="checkbox")
        plex_host = _setting_input("plex", "host", settings.plex.host, placeholder="192.168.1.x")
        nmap_interval = _setting_input("nmap", "scan_interval_hours", settings.nmap.scan_interval_hours, input_type="number")

        return f'''<h2>Collectors</h2>
        <table class="sh-table">
            <tr><td class="text-muted text-xs">UniFi</td><td>{unifi_toggle}</td></tr>
            <tr><td class="text-muted text-xs">UniFi host</td><td>{unifi_host}</td></tr>
            <tr><td class="text-muted text-xs">UniFi poll interval</td><td>{unifi_poll} <span class="text-xs text-muted">seconds</span></td></tr>
            <tr><td class="text-muted text-xs">Pi-hole</td><td>{pihole_toggle}</td></tr>
            <tr><td class="text-muted text-xs">Pi-hole host</td><td>{pihole_host}</td></tr>
            <tr><td class="text-muted text-xs">Plex</td><td>{plex_toggle}</td></tr>
            <tr><td class="text-muted text-xs">Plex host</td><td>{plex_host}</td></tr>
            <tr><td class="text-muted text-xs">Nmap interval</td><td>{nmap_interval} <span class="text-xs text-muted">hours</span></td></tr>
            <tr><td class="text-muted text-xs">Nmap ports</td><td class="text-xs">{len(settings.nmap.ports)} configured</td></tr>
            <tr><td class="text-muted text-xs">SMB whitelist</td><td class="text-xs">{", ".join(settings.network.smb_whitelist) if settings.network.smb_whitelist else "none"}</td></tr>
        </table>'''
    except Exception as exc:
        return f'<h2>Collectors</h2><p class="text-muted text-sm">Error: {exc}</p>'


@router.get("/dashboard/partials/settings-rules", response_class=HTMLResponse)
async def partial_settings_rules():
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Rule

        with session_scope() as session:
            rules = session.query(Rule).order_by(Rule.priority.asc(), Rule.name.asc()).all()
            rule_data = [{
                "id": r.id, "name": r.name, "severity": r.severity,
                "source": r.source, "enabled": r.enabled, "approved": r.approved,
                "frozen": r.frozen, "action": r.action, "fire_count": r.fire_count,
                "cooldown_seconds": r.cooldown_seconds,
                "description": r.description,
                "tp": r.true_positive_count, "fp": r.false_positive_count,
            } for r in rules]

        if not rule_data:
            return '<h2>Rules</h2><p class="text-muted text-sm">No rules configured. Default rules will be seeded on first full startup.</p>'

        target = 'hx-target="[hx-get=\'/dashboard/partials/settings-rules\']" hx-swap="innerHTML"'

        rows = ""
        for r in rule_data:
            sev_cls = f"sev-{r['severity']}"
            row_id = f"rule-{r['id']}"
            name_safe = r["name"].replace(":", "").replace(" ", "-").replace("/", "-")
            notes_id = f"rule-notes-{name_safe}"
            note_input_id = f"rule-note-input-{name_safe}"
            encoded_name = h(r["name"])
            enabled_btn = (
                f'<button class="sh-btn sh-btn-ok text-xs" hx-post="/dashboard/actions/toggle-rule/{r["id"]}" {target} onclick="event.stopPropagation()">on</button>'
                if r['enabled'] else
                f'<button class="sh-btn sh-btn-danger text-xs" hx-post="/dashboard/actions/toggle-rule/{r["id"]}" {target} onclick="event.stopPropagation()">off</button>'
            )
            source_badge = f'<span class="badge badge-{"info" if r["source"]=="system" else "accent"}">{r["source"]}</span>'
            frozen_btn = (
                f'<button class="sh-btn text-xs" hx-post="/dashboard/actions/unfreeze-rule/{r["id"]}" {target} title="Click to unfreeze" onclick="event.stopPropagation()">frozen</button>'
                if r["frozen"] else
                f'<button class="sh-btn text-xs" hx-post="/dashboard/actions/freeze-rule/{r["id"]}" {target} title="Click to freeze" style="opacity:0.4" onclick="event.stopPropagation()">lock</button>'
            )
            approved = "" if r["approved"] else ' <span class="badge badge-warn">pending</span>'
            tp = r.get("tp", 0) or 0
            fp = r.get("fp", 0) or 0
            feedback = f"{tp}/{fp}" if (tp + fp) > 0 else "-"

            rows += f'''<tr class="expand-row" onclick="document.getElementById('{row_id}').classList.toggle('open')">
                <td class="text-sm">{encoded_name}{approved}</td>
                <td>{source_badge}</td>
                <td class="{sev_cls} text-xs">{h(r["severity"])}</td>
                <td class="text-xs">{h(r["action"])}</td>
                <td>{enabled_btn}</td>
                <td class="text-xs">{r["fire_count"]}</td>
                <td class="text-xs text-muted">{feedback}</td>
                <td>{frozen_btn}</td>
            </tr>'''

            # Expandable detail row with description + notes
            desc_html = h(r["description"][:500]) if r["description"] else "No description."
            rows += f'''<tr id="{row_id}" class="expand-detail">
                <td colspan="8">
                    <dl class="detail-grid">
                        <dt>Description</dt><dd class="text-sm">{desc_html}</dd>
                        <dt>Cooldown</dt><dd class="text-xs">{r["cooldown_seconds"]}s</dd>
                    </dl>
                    <p class="text-xs text-muted" style="margin:0.75rem 0 0.3rem">Notes</p>
                    <div id="{notes_id}"
                         hx-get="/dashboard/partials/rule-notes/{encoded_name}"
                         hx-trigger="intersect once"
                         hx-swap="innerHTML">
                        <span class="text-xs text-muted">Loading notes...</span>
                    </div>
                    <form style="margin-top:0.5rem" onclick="event.stopPropagation()"
                          hx-post="/dashboard/actions/add-rule-note/{encoded_name}"
                          hx-swap="none"
                          hx-on::after-request="document.getElementById('{note_input_id}').value=''; htmx.ajax('GET', '/dashboard/partials/rule-notes/{encoded_name}', '#{notes_id}')">
                        <textarea id="{note_input_id}" class="edit-textarea" name="text" placeholder="Add a note about this rule..." rows="2" onclick="event.stopPropagation()"></textarea>
                        <button class="sh-btn sh-btn-ok" type="submit" style="margin-top:0.3rem">Save Note</button>
                    </form>
                </td>
            </tr>'''

        return f'''<h2>Rules <span class="text-xs text-muted">{len(rule_data)} configured — click a row to expand</span></h2>
        <table class="sh-table">
            <tr><th>Name</th><th>Source</th><th>Sev</th><th>Action</th><th>Enabled</th><th>Fires</th><th>TP/FP</th><th>Lock</th></tr>
            {rows}
        </table>'''
    except Exception as exc:
        return f'<h2>Rules</h2><p class="text-muted text-sm">Error: {exc}</p>'


@router.get("/dashboard/partials/settings-retention", response_class=HTMLResponse)
async def partial_settings_retention():
    try:
        from sentinel_home.config import get_settings
        settings = get_settings()
        r = settings.retention

        ev = _setting_input("retention", "events_days", r.events_days, input_type="number")
        ro = _setting_input("retention", "rollups_days", r.rollups_days, input_type="number")
        fi = _setting_input("retention", "findings_days", r.findings_days, input_type="number")
        sj = _setting_input("retention", "stale_jobs_days", r.stale_jobs_days, input_type="number")

        return f'''<h2>Retention</h2>
        <table class="sh-table">
            <tr><td class="text-muted text-xs">Events</td><td>{ev} <span class="text-xs text-muted">days</span></td></tr>
            <tr><td class="text-muted text-xs">Rollups</td><td>{ro} <span class="text-xs text-muted">days</span></td></tr>
            <tr><td class="text-muted text-xs">Findings</td><td>{fi} <span class="text-xs text-muted">days</span></td></tr>
            <tr><td class="text-muted text-xs">Stale Jobs</td><td>{sj} <span class="text-xs text-muted">days</span></td></tr>
        </table>'''
    except Exception as exc:
        return f'<h2>Retention</h2><p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# Agent panel partials
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/settings-agent", response_class=HTMLResponse)
async def partial_settings_agent():
    try:
        from sentinel_home.config import get_settings
        settings = get_settings()

        agent_toggle = _setting_input("agent", "enabled", settings.agent.enabled, input_type="checkbox")
        agent_url = _setting_input("agent", "url", settings.agent.url, placeholder="http://192.168.1.x:8084")
        agent_model = _setting_input("agent", "model", settings.agent.model, placeholder="sentinel-analyst")
        agent_chat_model = _setting_input("agent", "chat_model", settings.agent.chat_model, placeholder="sentinel-chat")
        agent_inv_model = _setting_input("agent", "investigator_model", settings.agent.investigator_model, placeholder="sentinel-investigator")

        if not settings.agent.enabled:
            return f'''<h2>Agent</h2>
            <table class="sh-table">
                <tr><td class="text-muted text-xs">Enabled</td><td>{agent_toggle}</td></tr>
                <tr><td class="text-muted text-xs">URL</td><td>{agent_url}</td></tr>
                <tr><td class="text-muted text-xs">Analyst model</td><td>{agent_model}</td></tr>
                <tr><td class="text-muted text-xs">Chat model</td><td>{agent_chat_model}</td></tr>
                <tr><td class="text-muted text-xs">Investigator model</td><td>{agent_inv_model}</td></tr>
            </table>
            <p class="text-xs text-muted">Toggle to enable. Requires restart for scheduler to pick up changes.</p>'''

        try:
            from sentinel_home.agent.scheduler import get_agent_status
            status = get_agent_status()
            actor = status["actor"]
            critic = status["critic"]
            actor_run = actor["last_run"] or "never"
            critic_run = critic["last_run"] or "never"
            actor_stats = f'{actor.get("success_count", 0)}✓ / {actor.get("fail_count", 0)}✗'
            critic_stats = f'{critic.get("success_count", 0)}✓ / {critic.get("fail_count", 0)}✗'
        except Exception:
            actor_run = critic_run = "error"
            actor_stats = critic_stats = "—"
            actor = {"interval_minutes": settings.agent.actor.interval_minutes}
            critic = {"interval_hours": settings.agent.critic.interval_hours,
                      "auto_tuning": settings.agent.critic.auto_tuning,
                      "conservatism": settings.agent.critic.conservatism,
                      "require_consensus": settings.agent.critic.require_consensus}

        actor_interval = _setting_input("agent.actor", "interval_minutes", actor["interval_minutes"], input_type="number")
        critic_interval = _setting_input("agent.critic", "interval_hours", critic["interval_hours"], input_type="number")
        conservatism_select = _setting_input("agent.critic", "conservatism", critic["conservatism"],
                                             options=["conservative", "moderate", "aggressive"])
        auto_tune = _setting_input("agent.critic", "auto_tuning", critic["auto_tuning"], input_type="checkbox")
        consensus = _setting_input("agent.critic", "require_consensus", critic["require_consensus"], input_type="checkbox")
        max_changes = _setting_input("agent.critic", "max_rule_changes_per_day",
                                     settings.agent.critic.max_rule_changes_per_day, input_type="number")

        # LLM health check
        try:
            from sentinel_home.agent.llm_adapter import get_llm_adapter
            adapter = get_llm_adapter()
            llm_status = '<span class="badge badge-ok">connected</span>' if adapter and adapter.is_available() else '<span class="badge badge-err">unreachable</span>'
        except Exception:
            llm_status = '<span class="badge badge-info">unknown</span>'

        return f'''<h2>Agent <span class="badge badge-info">enabled</span> {llm_status}</h2>
        <table class="sh-table">
            <tr><td class="text-muted text-xs">Enabled</td><td>{agent_toggle}</td></tr>
            <tr><td class="text-muted text-xs">URL</td><td>{agent_url}</td></tr>
            <tr><td class="text-muted text-xs">Analyst model</td><td>{agent_model}</td></tr>
            <tr><td class="text-muted text-xs">Chat model</td><td>{agent_chat_model}</td></tr>
            <tr><td class="text-muted text-xs">Investigator model</td><td>{agent_inv_model}</td></tr>
            <tr><td class="text-muted text-xs">Actor interval</td><td>{actor_interval} <span class="text-xs text-muted">min</span></td></tr>
            <tr><td class="text-muted text-xs">Actor last run</td><td class="text-xs">{actor_run}</td></tr>
            <tr><td class="text-muted text-xs">Actor runs</td><td class="text-xs">{actor_stats}</td></tr>
            <tr><td class="text-muted text-xs">Critic interval</td><td>{critic_interval} <span class="text-xs text-muted">hours</span></td></tr>
            <tr><td class="text-muted text-xs">Critic last run</td><td class="text-xs">{critic_run}</td></tr>
            <tr><td class="text-muted text-xs">Critic runs</td><td class="text-xs">{critic_stats}</td></tr>
            <tr><td class="text-muted text-xs">Auto-tuning</td><td>{auto_tune}</td></tr>
            <tr><td class="text-muted text-xs">Conservatism</td><td>{conservatism_select}</td></tr>
            <tr><td class="text-muted text-xs">Consensus</td><td>{consensus}</td></tr>
            <tr><td class="text-muted text-xs">Max changes/day</td><td>{max_changes}</td></tr>
        </table>
        <p class="text-xs text-muted">Some changes require restart to take effect (intervals, enable/disable).</p>'''
    except Exception as exc:
        return f'<h2>Agent</h2><p class="text-muted text-sm">Error: {exc}</p>'


@router.get("/dashboard/partials/agent-suggestions", response_class=HTMLResponse)
async def partial_agent_suggestions():
    """Show agent-created rules that need user approval."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Rule

        with session_scope() as session:
            pending = (
                session.query(Rule)
                .filter(Rule.approved == False)
                .order_by(Rule.id.desc())
                .all()
            )
            pending_data = [{
                "id": r.id, "name": r.name, "severity": r.severity,
                "description": r.description, "source": r.source,
                "parameters": r.parameters, "action": r.action,
                "created_by": r.created_by,
            } for r in pending]

        if not pending_data:
            return ''  # Hide the card entirely when no suggestions

        rows = ""
        for r in pending_data:
            sev_cls = f"sev-{r['severity']}"
            rows += f'''<tr>
                <td class="text-sm">{h(r["name"])}</td>
                <td class="{sev_cls} text-xs">{h(r["severity"])}</td>
                <td class="text-xs text-muted" style="max-width:300px;overflow:hidden;text-overflow:ellipsis">{h(r["description"][:120])}</td>
                <td class="text-xs">{h(r["action"])}</td>
                <td>
                    <button class="sh-btn sh-btn-ok text-xs"
                            hx-post="/dashboard/actions/approve-rule/{r["id"]}"
                            hx-target="#agent-suggestions"
                            hx-swap="innerHTML">Approve</button>
                    <button class="sh-btn sh-btn-danger text-xs"
                            hx-delete="/dashboard/actions/reject-rule/{r["id"]}"
                            hx-target="#agent-suggestions"
                            hx-swap="innerHTML"
                            hx-confirm="Delete this suggested rule?">Reject</button>
                </td>
            </tr>'''

        return f'''<h2>Agent Suggestions <span class="badge badge-warn">{len(pending_data)} pending</span></h2>
        <p class="text-xs text-muted" style="margin-bottom:0.5rem">Rules suggested by the agent. Approve to activate, reject to delete.</p>
        <table class="sh-table">
            <tr><th>Name</th><th>Sev</th><th>Description</th><th>Action</th><th></th></tr>
            {rows}
        </table>'''
    except Exception as exc:
        return f'<p class="text-muted text-sm">Error loading suggestions: {exc}</p>'


@router.post("/dashboard/actions/approve-rule/{rule_id}", response_class=HTMLResponse)
async def action_approve_rule(rule_id: int):
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Rule

        with session_scope() as session:
            rule = session.query(Rule).filter(Rule.id == rule_id).first()
            if rule:
                rule.approved = True
    except Exception as exc:
        return f'<p class="text-sm sev-high">Error approving rule: {h(str(exc))}</p>'

    return await partial_agent_suggestions()


@router.delete("/dashboard/actions/reject-rule/{rule_id}", response_class=HTMLResponse)
async def action_reject_rule(rule_id: int):
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Rule

        with session_scope() as session:
            rule = session.query(Rule).filter(Rule.id == rule_id).first()
            if rule and rule.source != "system":
                session.delete(rule)
    except Exception as exc:
        return f'<p class="text-sm sev-high">Error rejecting rule: {h(str(exc))}</p>'

    return await partial_agent_suggestions()


# ---------------------------------------------------------------------------
# Rule actions (freeze/unfreeze from dashboard)
# ---------------------------------------------------------------------------

@router.post("/dashboard/actions/freeze-rule/{rule_id}", response_class=HTMLResponse)
async def action_freeze_rule(rule_id: int):
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Rule

        with session_scope() as session:
            rule = session.query(Rule).filter(Rule.id == rule_id).first()
            if rule:
                rule.frozen = True
    except Exception as exc:
        return f'<p class="text-sm sev-high">Error: {h(str(exc))}</p>'

    return await partial_settings_rules()


@router.post("/dashboard/actions/unfreeze-rule/{rule_id}", response_class=HTMLResponse)
async def action_unfreeze_rule(rule_id: int):
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Rule

        with session_scope() as session:
            rule = session.query(Rule).filter(Rule.id == rule_id).first()
            if rule:
                rule.frozen = False
    except Exception as exc:
        return f'<p class="text-sm sev-high">Error: {h(str(exc))}</p>'

    return await partial_settings_rules()


@router.post("/dashboard/actions/toggle-rule/{rule_id}", response_class=HTMLResponse)
async def action_toggle_rule(rule_id: int):
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Rule

        with session_scope() as session:
            rule = session.query(Rule).filter(Rule.id == rule_id).first()
            if rule:
                rule.enabled = not rule.enabled
    except Exception as exc:
        return f'<p class="text-sm sev-high">Error: {h(str(exc))}</p>'

    return await partial_settings_rules()


# ---------------------------------------------------------------------------
# Notifications settings partial + test action
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/settings-new-devices", response_class=HTMLResponse)
async def partial_settings_new_devices():
    """List recently-seen devices with no label or type — quick review workflow."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Device
        from datetime import datetime, timedelta, timezone

        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        with session_scope() as session:
            unknown = (
                session.query(Device)
                .filter(
                    (Device.label == None) | (Device.device_type == None) | (Device.device_type == "unknown"),
                    Device.first_seen >= cutoff,
                )
                .order_by(Device.first_seen.desc())
                .limit(50)
                .all()
            )
            devices = [{
                "mac": d.mac, "ip": d.ip or "?", "vendor": d.vendor or "unknown",
                "device_type": d.device_type or "unknown",
                "label": d.label or "",
                "first_seen": d.first_seen.strftime("%m-%d %H:%M") if d.first_seen else "?",
                "last_seen": d.last_seen.strftime("%m-%d %H:%M") if d.last_seen else "?",
            } for d in unknown]

        if not devices:
            return ''  # Hide card when nothing to review

        rows = ""
        for d in devices:
            rows += f'''<tr>
                <td class="text-xs" style="font-family:monospace">{h(d["mac"])}</td>
                <td class="text-xs">{h(d["ip"])}</td>
                <td class="text-xs text-muted">{h(d["vendor"][:24])}</td>
                <td class="text-xs text-muted nowrap">{h(d["first_seen"])}</td>
                <td>
                    <form hx-post="/dashboard/actions/label-device/{h(d["mac"])}"
                          hx-target="#new-devices-card"
                          hx-swap="innerHTML"
                          style="display:flex;gap:0.3rem;align-items:center">
                        <input class="edit-input" name="label" placeholder="label…"
                               style="width:110px;padding:0.2rem 0.4rem;font-size:0.75rem">
                        <select class="edit-select" name="device_type"
                                style="padding:0.2rem 0.3rem;font-size:0.75rem">
                            <option value="">type…</option>
                            <option value="phone">phone</option>
                            <option value="laptop">laptop</option>
                            <option value="desktop">desktop</option>
                            <option value="server">server</option>
                            <option value="router">router</option>
                            <option value="ap">ap</option>
                            <option value="switch">switch</option>
                            <option value="iot">iot</option>
                            <option value="media">media</option>
                            <option value="printer">printer</option>
                            <option value="camera">camera</option>
                            <option value="tablet">tablet</option>
                            <option value="unknown">skip</option>
                        </select>
                        <button type="submit" class="sh-btn sh-btn-ok text-xs" style="padding:0.2rem 0.5rem">Save</button>
                    </form>
                </td>
            </tr>'''

        return f'''<h2>New Devices <span class="badge badge-warn">{len(devices)} unlabelled</span></h2>
        <p class="text-xs text-muted" style="margin-bottom:0.5rem">Devices seen in the last 30 days without a label or type. Label them to improve rule targeting.</p>
        <table class="sh-table">
            <tr><th>MAC</th><th>IP</th><th>Vendor</th><th>First seen</th><th>Label / Type</th></tr>
            {rows}
        </table>'''
    except Exception as exc:
        return f'<h2>New Devices</h2><p class="text-muted text-sm">Error: {exc}</p>'


@router.post("/dashboard/actions/label-device/{mac}", response_class=HTMLResponse)
async def action_label_device(mac: str, label: str = Form(""), device_type: str = Form("")):
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Device
        with session_scope() as session:
            device = session.query(Device).filter(Device.mac == mac).first()
            if device:
                if label.strip():
                    device.label = label.strip()
                if device_type and device_type != "":
                    device.device_type = device_type
                device.updated_by = "user"
    except Exception as exc:
        return f'<p class="text-sm sev-high">Error: {h(str(exc))}</p>'
    return await partial_settings_new_devices()


@router.get("/dashboard/partials/settings-notifications", response_class=HTMLResponse)
async def partial_settings_notifications():
    try:
        from sentinel_home.config import get_settings
        settings = get_settings()
        cfg = getattr(settings, "notifications", None)
        enabled = getattr(cfg, "enabled", False) if cfg else False
        urls = getattr(cfg, "urls", []) if cfg else []
        min_sev = getattr(cfg, "min_severity", "high") if cfg else "high"

        url_list = ""
        if urls:
            for u in urls:
                # Mask credentials in display
                import re
                masked = re.sub(r'(://[^:@/]+:)[^@/]+(@)', r'\1***\2', u)
                url_list += f'<li class="text-xs text-muted" style="font-family:monospace">{h(masked)}</li>'
            url_list = f'<ul style="margin:0.25rem 0 0 1rem;padding:0">{url_list}</ul>'
        else:
            url_list = '<span class="text-xs text-muted">None configured — add notification URLs to config.yaml</span>'

        status_badge = '<span class="badge badge-ok">enabled</span>' if enabled else '<span class="badge badge-info">disabled</span>'
        url_count = f'{len(urls)} target{"s" if len(urls) != 1 else ""}' if urls else "no targets"

        return f'''<h2>Notifications {status_badge}</h2>
        <p class="text-xs text-muted" style="margin-bottom:0.5rem">
            Apprise-powered push notifications. Min severity: <strong>{h(min_sev)}</strong>. {h(url_count)}.
        </p>
        {url_list}
        <div style="margin-top:0.75rem;display:flex;gap:0.5rem;align-items:center">
            <button class="sh-btn"
                    hx-post="/dashboard/actions/test-notifications"
                    hx-target="#notif-test-result"
                    hx-swap="innerHTML"
                    {"disabled" if not enabled or not urls else ""}>Send test notification</button>
            <span id="notif-test-result"></span>
        </div>
        <p class="text-xs text-muted" style="margin-top:0.5rem">Configure in config.yaml under <code>notifications.urls</code>. Requires restart.</p>'''
    except Exception as exc:
        return f'<h2>Notifications</h2><p class="text-muted text-sm">Error: {exc}</p>'


@router.post("/dashboard/actions/test-notifications", response_class=HTMLResponse)
async def action_test_notifications():
    try:
        from sentinel_home.notifications.router import send_alert, _get_apprise, should_notify
        from sentinel_home.config import get_settings
        settings = get_settings()
        cfg = getattr(settings, "notifications", None)
        urls = getattr(cfg, "urls", []) if cfg else []

        if not urls:
            return '<span class="text-xs sev-medium">No notification URLs configured.</span>'

        # Send a test alert bypassing severity filter
        ap = _get_apprise()
        if ap is None:
            return '<span class="text-xs sev-high">Failed to initialise Apprise — check logs.</span>'

        import apprise
        result = ap.notify(
            title="SentinelHome — Test Notification",
            body="This is a test notification from SentinelHome. If you see this, notifications are working.",
            notify_type=apprise.NotifyType.INFO,
        )
        if result:
            return '<span class="text-xs sev-low">Test notification sent successfully.</span>'
        else:
            return '<span class="text-xs sev-high">Notification send failed — check URL config and logs.</span>'
    except Exception as exc:
        return f'<span class="text-xs sev-high">Error: {h(str(exc))}</span>'


# ---------------------------------------------------------------------------
# Auth actions
# ---------------------------------------------------------------------------

@router.post("/dashboard/actions/set-password")
async def action_set_password(
    new_password: str = Form(...),
    current_password: str = Form(None),
):
    from sentinel_home.auth import is_auth_enabled, get_password_hash, set_password, _verify_password

    if is_auth_enabled():
        stored = get_password_hash()
        if not stored or not _verify_password(current_password or "", stored):
            return {"ok": False, "message": "Current password incorrect"}

    if len(new_password) < 4:
        return {"ok": False, "message": "Password too short (min 4)"}

    if set_password(new_password):
        return {"ok": True, "message": "Password saved"}
    return {"ok": False, "message": "Error saving password"}


# ---------------------------------------------------------------------------
# Settings — save config.yaml
# ---------------------------------------------------------------------------

def _load_raw_config() -> dict:
    """Load config.yaml as raw dict (or empty if not found)."""
    import yaml
    import os
    config_path = Path(os.environ.get("CONFIG_PATH", "config.yaml"))
    if config_path.exists():
        with config_path.open() as f:
            return yaml.safe_load(f) or {}
    return {}


def _save_raw_config(raw: dict) -> None:
    """Write config dict back to config.yaml."""
    import yaml
    import os
    config_path = Path(os.environ.get("CONFIG_PATH", "config.yaml"))
    with config_path.open("w") as f:
        yaml.dump(raw, f, default_flow_style=False, sort_keys=False)


@router.post("/dashboard/actions/save-setting", response_class=HTMLResponse)
async def action_save_setting(section: str = Form(...), key: str = Form(...), value: str = Form("")):
    """Save a single config value to config.yaml and reload settings.

    Section.key format: e.g. section="agent", key="enabled", value="true"
    Nested keys use dots: section="agent.critic", key="conservatism", value="moderate"
    """
    # Whitelist of sections/keys that can be edited from the dashboard
    allowed = {
        "pihole.enabled", "pihole.host", "pihole.password",
        "unifi.enabled", "unifi.host", "unifi.poll_interval_seconds",
        "plex.enabled", "plex.host", "plex.port", "plex.token",
        "nmap.scan_interval_hours",
        "agent.enabled", "agent.url", "agent.model",
        "agent.chat_model", "agent.investigator_model",
        "agent.actor.interval_minutes",
        "agent.critic.interval_hours", "agent.critic.conservatism",
        "agent.critic.auto_tuning", "agent.critic.require_consensus",
        "agent.critic.max_rule_changes_per_day",
        "retention.events_days", "retention.rollups_days",
        "retention.findings_days", "retention.stale_jobs_days",
        "server.log_level",
        "network.smb_whitelist",
    }

    full_key = f"{section}.{key}" if section else key
    if full_key not in allowed:
        return HTMLResponse(f'<span class="text-xs sev-high">not editable: {h(full_key)}</span>', status_code=400)

    try:
        raw = _load_raw_config()

        # Navigate to the right section
        parts = section.split(".") if section else []
        target = raw
        for part in parts:
            target = target.setdefault(part, {})

        # Type conversion
        if value.lower() in ("true", "false"):
            target[key] = value.lower() == "true"
        elif value.isdigit():
            target[key] = int(value)
        else:
            try:
                target[key] = float(value)
            except ValueError:
                target[key] = value

        _save_raw_config(raw)

        # Reload settings in memory
        from sentinel_home.config import reload_settings
        reload_settings()

        return HTMLResponse('<span class="save-msg">saved</span>', status_code=200)
    except Exception as exc:
        return HTMLResponse(f'<span class="text-xs sev-high">Error: {h(str(exc))}</span>', status_code=500)


# ---------------------------------------------------------------------------
# Agent Chat — persistent conversation across page navigation
# ---------------------------------------------------------------------------

# In-memory chat history (list of {"role": "user"|"assistant", "text": str, "meta": str|None, "ts": str})
# This is a local display cache — the authoritative copy lives in Open WebUI.
_chat_history: list[dict] = []
MAX_CHAT_MESSAGES = 50

# Open WebUI chat_id for the current dashboard conversation.
# When set, all messages are saved to Open WebUI and appear in its sidebar.
_owui_chat_id: str | None = None


def _build_network_context() -> str:
    """Build a text summary of the current network state for LLM context."""
    context_parts = []
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Device, Event, Alert

        with session_scope() as session:
            devices = session.query(Device).order_by(Device.last_seen.desc()).limit(50).all()
            if devices:
                dev_lines = []
                for d in devices:
                    label = d.label or d.vendor or d.mac[:8]
                    dev_lines.append(f"- {label}: IP={d.ip or '?'}, MAC={d.mac}, type={d.device_type or '?'}, last_seen={_ago(d.last_seen)}")
                context_parts.append(f"DEVICES ({len(devices)} total):\n" + "\n".join(dev_lines[:30]))

            events = session.query(Event).order_by(Event.ts.desc()).limit(20).all()
            if events:
                ev_lines = []
                for e in events:
                    ev_lines.append(f"- [{e.severity or 'info'}] {e.event_type}: {(e.message or '')[:100]} (device={e.device_id or '?'}, {_ago(e.ts)})")
                context_parts.append(f"RECENT EVENTS ({len(events)}):\n" + "\n".join(ev_lines))

            alerts = session.query(Alert).order_by(Alert.ts.desc()).limit(10).all()
            if alerts:
                al_lines = []
                for a in alerts:
                    al_lines.append(f"- [{a.severity}] {a.rule_name}: {(a.message or '')[:100]} (device={a.device_id or '?'}, {_ago(a.ts)})")
                context_parts.append(f"RECENT ALERTS ({len(alerts)}):\n" + "\n".join(al_lines))

    except Exception:
        context_parts.append("(Could not load network context)")

    return "\n\n".join(context_parts)


def _render_chat_messages() -> str:
    """Render the full chat history as HTML."""
    if not _chat_history:
        return '<p class="text-muted text-sm" style="text-align:center;padding:2rem 0">Ask anything about your network.</p>'

    html = ""
    for msg in _chat_history:
        if msg["role"] == "user":
            html += f'''<div style="display:flex;justify-content:flex-end;margin-bottom:0.5rem">
                <div style="background:rgba(88,166,255,0.12);border:1px solid rgba(88,166,255,0.25);border-radius:12px 12px 2px 12px;padding:0.5rem 0.75rem;max-width:85%">
                    <div class="text-sm" style="color:var(--sh-text)">{h(msg["text"])}</div>
                    <div class="text-xs text-muted" style="text-align:right;margin-top:0.2rem">{msg.get("ts", "")}</div>
                </div>
            </div>'''
        else:
            answer_html = h(msg["text"]).replace("\n", "<br>")
            meta_html = f'<div class="text-xs text-muted" style="margin-top:0.25rem">{h(msg.get("meta", ""))}</div>' if msg.get("meta") else ""
            html += f'''<div style="display:flex;justify-content:flex-start;margin-bottom:0.5rem">
                <div style="background:var(--sh-bg);border:1px solid var(--sh-border);border-radius:12px 12px 12px 2px;padding:0.5rem 0.75rem;max-width:85%">
                    <div class="text-sm" style="line-height:1.5;color:var(--sh-text)">{answer_html}</div>
                    {meta_html}
                </div>
            </div>'''
    return html


@router.get("/dashboard/partials/chat-messages", response_class=HTMLResponse)
async def partial_chat_messages():
    """Return the full chat history HTML."""
    return _render_chat_messages()


@router.post("/dashboard/actions/chat-send", response_class=HTMLResponse)
async def action_chat_send(question: str = Form(...)):
    """Send a chat message, get LLM response, return updated conversation.

    Uses chat_with_persistence() so the conversation is saved in Open WebUI,
    visible in its sidebar, and available for Memory/RAG/search.
    """
    global _owui_chat_id

    now_str = datetime.now(timezone.utc).strftime("%H:%M")

    if not question.strip():
        return _render_chat_messages()

    # Add user message
    _chat_history.append({"role": "user", "text": question.strip(), "ts": now_str})

    try:
        from sentinel_home.agent.llm_adapter import get_llm_adapter

        adapter = get_llm_adapter()
        if not adapter:
            _chat_history.append({"role": "assistant", "text": "Agent is not configured. Enable it in Settings → Agent.", "ts": now_str})
            return _render_chat_messages()

        if not adapter.is_available():
            _chat_history.append({"role": "assistant", "text": "Agent LLM is not reachable. Check your agent URL.", "ts": now_str})
            return _render_chat_messages()

        # Build the OpenAI-format messages list.
        context = _build_network_context()

        messages = [
            {"role": "system", "content": (
                "You are the SentinelHome network assistant. "
                "Reference specific device names, IPs, and MACs. "
                "Be conversational and helpful.\n\n"
                f"CURRENT NETWORK STATE:\n{context}"
            )},
        ]

        # Replay conversation history as proper chat turns (last 10 exchanges)
        recent = _chat_history[-21:]  # up to 10 exchanges + current user msg
        for msg in recent:
            messages.append({"role": msg["role"], "content": msg["text"]})

        loop = asyncio.get_event_loop()
        response, new_chat_id = await loop.run_in_executor(
            None,
            lambda: adapter.chat_with_persistence(
                messages=messages,
                chat_id=_owui_chat_id,
            ),
        )

        # Persist the chat_id so subsequent messages continue the same chat
        if new_chat_id:
            _owui_chat_id = new_chat_id

        if not response.success:
            _chat_history.append({"role": "assistant", "text": f"LLM error: {response.error or 'unknown'}", "ts": now_str})
        else:
            meta = f"{response.model} | {response.tokens_used} tokens | {response.latency_seconds:.1f}s"
            _chat_history.append({"role": "assistant", "text": response.text, "meta": meta, "ts": now_str})

    except Exception as exc:
        _chat_history.append({"role": "assistant", "text": f"Error: {str(exc)}", "ts": now_str})

    # Cap history
    if len(_chat_history) > MAX_CHAT_MESSAGES:
        _chat_history[:] = _chat_history[-MAX_CHAT_MESSAGES:]

    return _render_chat_messages()


@router.post("/dashboard/actions/chat-clear", response_class=HTMLResponse)
async def action_chat_clear():
    """Clear the chat history and start a fresh Open WebUI chat."""
    global _owui_chat_id
    _chat_history.clear()
    _owui_chat_id = None  # next message will create a new Open WebUI chat
    return _render_chat_messages()


# ---------------------------------------------------------------------------
# Daily summary partial (overview page)
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/daily-summary", response_class=HTMLResponse)
async def partial_daily_summary():
    """Show the latest daily summary on the overview page."""
    try:
        from sentinel_home.api.routes.reports import _summaries

        if not _summaries:
            return '''<h2>Daily Summary</h2>
            <p class="text-sm text-muted">No summary generated yet. Summaries run daily at 8 AM, or
            <button class="sh-btn sh-btn-ok" style="display:inline"
                    hx-post="/dashboard/actions/generate-summary"
                    hx-target="closest .sh-card"
                    hx-swap="innerHTML">generate now</button></p>'''

        s = _summaries[-1]
        text = s.get("llm_summary") or s.get("stats", "No data")
        text_html = h(text).replace("\n", "<br>")
        gen_at = s.get("generated_at", "")[:16].replace("T", " ")
        model_info = f' | {s["model"]}' if s.get("model") else ""

        return f'''<h2>Daily Summary <span class="text-xs text-muted">({gen_at}{model_info})</span></h2>
        <div class="text-sm" style="line-height:1.5">{text_html}</div>
        <div style="margin-top:0.5rem">
            <button class="sh-btn"
                    hx-post="/dashboard/actions/generate-summary"
                    hx-target="closest .sh-card"
                    hx-swap="innerHTML">refresh</button>
        </div>'''
    except Exception as exc:
        return f'<h2>Daily Summary</h2><p class="text-muted text-sm">Error: {exc}</p>'


@router.post("/dashboard/actions/generate-summary", response_class=HTMLResponse)
async def action_generate_summary():
    """Trigger a summary generation and return the result."""
    import asyncio
    try:
        from sentinel_home.api.routes.reports import generate_summary
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, generate_summary, 24)

        text = result.get("llm_summary") or result.get("stats", "No data")
        text_html = h(text).replace("\n", "<br>")
        gen_at = result.get("generated_at", "")[:16].replace("T", " ")
        model_info = f' | {result["model"]}' if result.get("model") else ""

        return f'''<h2>Daily Summary <span class="text-xs text-muted">({gen_at}{model_info})</span></h2>
        <div class="text-sm" style="line-height:1.5">{text_html}</div>
        <div style="margin-top:0.5rem">
            <button class="sh-btn"
                    hx-post="/dashboard/actions/generate-summary"
                    hx-target="closest .sh-card"
                    hx-swap="innerHTML">refresh</button>
        </div>'''
    except Exception as exc:
        return f'<h2>Daily Summary</h2><p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# Rule creation form (settings page)
# ---------------------------------------------------------------------------

@router.post("/dashboard/actions/create-rule", response_class=HTMLResponse)
async def action_create_rule(
    name: str = Form(...),
    description: str = Form(""),
    severity: str = Form("medium"),
    category: str = Form("network"),
    action: str = Form("alert"),
    cooldown_seconds: int = Form(300),
    event_type: str = Form(""),
    threshold: int = Form(1),
    window_seconds: int = Form(3600),
):
    """Create a new user rule from the dashboard form."""
    if not name.strip():
        return '<span class="text-xs sev-high">Rule name is required</span>'

    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Rule

        # Build parameters based on inputs
        parameters = {"strategy": "windowed_count"}
        if event_type:
            parameters["event_type"] = event_type
        if threshold > 1:
            parameters["threshold"] = threshold
            parameters["window_seconds"] = window_seconds

        with session_scope() as session:
            existing = session.query(Rule).filter(Rule.name == name).first()
            if existing:
                return f'<span class="text-xs sev-high">Rule "{h(name)}" already exists</span>'

            rule = Rule(
                name=name.strip(),
                description=description,
                category=category,
                severity=severity,
                priority=2,
                source="user",
                enabled=True,
                approved=True,
                parameters=parameters,
                action=action,
                cooldown_seconds=cooldown_seconds,
                created_by="user",
            )
            session.add(rule)

        # Invalidate rule engine cache
        try:
            from sentinel_home.rules.engine import get_rule_engine
            get_rule_engine()._cache_ts = 0
        except Exception:
            pass

        return f'<span class="save-msg">Rule "{h(name)}" created</span>'
    except Exception as exc:
        return f'<span class="text-xs sev-high">Error: {h(str(exc))}</span>'


# ---------------------------------------------------------------------------
# Network topology visualization
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/topology", response_class=HTMLResponse)
async def partial_topology():
    """Render a simple topology visualization using device data."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Device

        with session_scope() as session:
            devices = session.query(Device).order_by(Device.last_seen.desc()).all()

            if not devices:
                return '<h2>Network Topology</h2><p class="text-muted text-sm">No devices discovered yet.</p>'

            # Group devices by type for layered display
            layers = {
                "Gateway": [],
                "Infrastructure": [],
                "Servers": [],
                "Clients": [],
                "IoT": [],
                "Unknown": [],
            }

            for d in devices:
                label = d.label or d.vendor or d.mac[:8]
                node = {
                    "mac": d.mac, "label": label, "ip": d.ip,
                    "type": d.device_type, "ap": d.ap,
                    "conn": d.connection_type, "role": d.network_role,
                }

                if d.device_type == "router":
                    layers["Gateway"].append(node)
                elif d.device_type in ("ap", "switch") or d.network_role == "infrastructure":
                    layers["Infrastructure"].append(node)
                elif d.device_type in ("server",):
                    layers["Servers"].append(node)
                elif d.device_type in ("phone", "laptop", "desktop", "tablet"):
                    layers["Clients"].append(node)
                elif d.device_type in ("iot", "media", "printer"):
                    layers["IoT"].append(node)
                else:
                    layers["Unknown"].append(node)

        type_colors = {
            "router": "var(--sh-red)", "ap": "var(--sh-orange)", "switch": "var(--sh-yellow)",
            "server": "var(--sh-purple)", "phone": "var(--sh-green)", "laptop": "var(--sh-accent)",
            "desktop": "var(--sh-accent)", "tablet": "var(--sh-green)",
            "iot": "#d2a8ff", "media": "var(--sh-orange)", "printer": "var(--sh-muted)",
        }

        html = '<h2>Network Topology</h2>'

        for layer_name, nodes in layers.items():
            if not nodes:
                continue
            html += f'<div style="margin-bottom:1rem"><span class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:0.05em">{layer_name}</span>'
            html += '<div style="display:flex;flex-wrap:wrap;gap:0.5rem;margin-top:0.3rem">'
            for n in nodes:
                color = type_colors.get(n["type"] or "", "var(--sh-muted)")
                conn_icon = "&#128246;" if n["conn"] == "wifi" else "&#128268;" if n["conn"] == "wired" else ""
                ap_info = f'<span class="text-xs text-muted"> &rarr; {h(n["ap"][:20])}</span>' if n["ap"] else ""
                html += f'''<div style="border:1px solid var(--sh-border);border-left:3px solid {color};border-radius:6px;padding:0.4rem 0.6rem;background:var(--sh-bg);min-width:140px">
                    <div class="text-sm" style="font-weight:600">{conn_icon} {h(n["label"])}</div>
                    <div class="text-xs text-muted mono">{n["ip"] or "—"}</div>
                    <div class="text-xs text-muted">{n["type"] or "unknown"}{ap_info}</div>
                </div>'''
            html += '</div></div>'

        return html
    except Exception as exc:
        return f'<h2>Network Topology</h2><p class="text-muted text-sm">Error: {exc}</p>'


# ---------------------------------------------------------------------------
# Reports partial (overview or dedicated page)
# ---------------------------------------------------------------------------

@router.get("/dashboard/partials/reports", response_class=HTMLResponse)
async def partial_reports():
    """Show available reports and generate on demand."""
    try:
        from sentinel_home.api.routes.reports import _summaries

        html = '<h2>Reports</h2>'
        html += '''<div class="flex gap-1 items-center" style="margin-bottom:0.75rem">
            <button class="sh-btn sh-btn-ok"
                    hx-post="/api/v1/reports/generate-summary?hours=24"
                    hx-target="#report-result"
                    hx-swap="innerHTML"
                    hx-indicator="#report-spinner">Daily Summary</button>
            <button class="sh-btn"
                    hx-post="/api/v1/reports/generate?days=7"
                    hx-target="#report-result"
                    hx-swap="innerHTML"
                    hx-indicator="#report-spinner">Weekly Report</button>
            <span style="margin-left:auto;display:flex;gap:0.25rem">
                <a href="/api/v1/export/devices?format=csv" class="sh-btn" download>Devices CSV</a>
                <a href="/api/v1/export/events?format=csv" class="sh-btn" download>Events CSV</a>
                <a href="/api/v1/export/alerts?format=csv" class="sh-btn" download>Alerts CSV</a>
                <a href="/api/v1/export/rules?format=csv" class="sh-btn" download>Rules CSV</a>
            </span>
            <span id="report-spinner" class="htmx-indicator text-xs text-muted">generating...</span>
        </div>'''

        if _summaries:
            html += f'<p class="text-xs text-muted mb-1">{len(_summaries)} summaries stored</p>'
            html += '<table class="sh-table"><tr><th>Generated</th><th>Period</th><th>Summary</th></tr>'
            for s in reversed(_summaries[-5:]):
                gen = s.get("generated_at", "")[:16].replace("T", " ")
                period = f'{s.get("period_hours", 24)}h'
                text = s.get("llm_summary") or s.get("stats", "")
                html += f'<tr><td class="text-xs text-muted nowrap">{gen}</td><td class="text-xs">{period}</td><td class="text-sm">{h(text[:200])}</td></tr>'
            html += '</table>'

        html += '<div id="report-result"></div>'
        return html
    except Exception as exc:
        return f'<h2>Reports</h2><p class="text-muted text-sm">Error: {exc}</p>'
