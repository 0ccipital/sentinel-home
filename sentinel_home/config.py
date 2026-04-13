"""Configuration loading — discovery-first config with env var overrides.

Designed for generic deployment: auto-detect LAN, interface, syslog mode.
No hardcoded network topology or vendor assumptions.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings


# ---------------------------------------------------------------------------
# Sub-config models
# ---------------------------------------------------------------------------

class NetworkConfig(BaseModel):
    sniff_interface: str = "auto"  # auto-detect first non-loopback
    lan_cidr: str = "auto"  # auto-detect from container/host IP
    wan_ip: str = "auto"
    smb_whitelist: list[str] = []  # IPs where SMB is expected (NAS, file servers)
    multi_nic_hosts: list[str] = []  # IPs with multiple physical NICs


class SyslogConfig(BaseModel):
    """Syslog ingestion — auto-detects UDP vs file mode."""
    mode: str = "auto"  # "auto" tries UDP first, falls back to file
    udp_port: int = 514  # UDP listener port (mode=auto or mode=udp)
    file_dir: str = "/mnt/syslog"  # Directory for file-based syslog (mode=auto or mode=file)
    poll_interval_seconds: int = 2


class NmapConfig(BaseModel):
    scan_interval_hours: int = 6
    ports: list[int] = [
        22, 53, 80, 443, 445, 3389,  # Standard services
        8080, 8443, 8890, 32400,  # Common web + media
    ]
    timeout_seconds: int = 300


class PiholeConfig(BaseModel):
    enabled: bool = False
    host: str = ""
    password: str = ""  # or env: PIHOLE_PASSWORD
    poll_interval_seconds: int = 60


class UniFiConfig(BaseModel):
    enabled: bool = False
    host: str = ""  # Gateway IP, e.g. "192.168.1.1"
    api_key: str = ""  # or env: UNIFI_API_KEY
    poll_interval_seconds: int = 60
    verify_ssl: bool = True  # Set to false if your gateway uses a self-signed cert


class PlexConfig(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = 32400
    token: str = ""  # or env: PLEX_TOKEN
    poll_interval_seconds: int = 120


class AgentActorConfig(BaseModel):
    interval_minutes: int = 15


class AgentCriticConfig(BaseModel):
    interval_hours: int = 12
    min_samples: int = 20
    fp_threshold: float = 0.5
    idle_threshold_days: int = 7
    require_consensus: bool = True
    conservatism: str = "moderate"  # conservative/moderate/aggressive
    auto_tuning: bool = True
    max_rule_changes_per_day: int = 5


class AgentConfig(BaseModel):
    """System 2 — optional LLM agent for analysis and rule tuning."""
    enabled: bool = False
    provider: str = "openwebui"  # openwebui/ollama/openai-compatible
    url: str = ""  # e.g. http://192.168.1.x:8084
    api_key: str = ""  # or env: AGENT_API_KEY
    model: str = ""                    # actor/critic micro-tasks (sentinel-analyst)
    chat_model: str = ""               # dashboard chat (sentinel-chat), falls back to model
    investigator_model: str = ""       # deep investigation (sentinel-investigator), falls back to model
    timeout_seconds: int = 600
    actor: AgentActorConfig = AgentActorConfig()
    critic: AgentCriticConfig = AgentCriticConfig()


class ThreatIntelConfig(BaseModel):
    enabled: bool = True
    update_interval_hours: int = 24
    sources: list[str] = [
        "firehol_level1",
        "spamhaus_drop",
        "emerging_threats",
        "known_scanners",
    ]


class RetentionConfig(BaseModel):
    events_days: int = 30
    rollups_days: int = 90
    findings_days: int = 365
    stale_jobs_days: int = 30


class NotificationsConfig(BaseModel):
    enabled: bool = False
    urls: list[str] = []  # Apprise URL strings (slack://, tgram://, etc.)
    min_severity: str = "high"  # Only notify for this severity and above


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8890
    api_key: str = ""
    db_path: str = "/data/sentinel.db"
    log_level: str = "INFO"
    memory_limit_mb: int = 0  # 0 = auto (1/4 RAM or 8GB, whichever higher)


# ---------------------------------------------------------------------------
# Root config
# ---------------------------------------------------------------------------

class Settings(BaseModel):
    network: NetworkConfig = NetworkConfig()
    syslog: SyslogConfig = SyslogConfig()
    nmap: NmapConfig = NmapConfig()
    pihole: PiholeConfig = PiholeConfig()
    unifi: UniFiConfig = UniFiConfig()
    plex: PlexConfig = PlexConfig()
    agent: AgentConfig = AgentConfig()
    threat_intel: ThreatIntelConfig = ThreatIntelConfig()
    retention: RetentionConfig = RetentionConfig()
    notifications: NotificationsConfig = NotificationsConfig()
    server: ServerConfig = ServerConfig()

    @classmethod
    def from_yaml(cls, path: Path | str = "config.yaml") -> "Settings":
        path = Path(path)
        raw: dict = {}
        if path.exists():
            with path.open() as f:
                raw = yaml.safe_load(f) or {}
        _apply_env_overrides(raw)
        return cls.model_validate(raw)


def _apply_env_overrides(raw: dict) -> None:
    """Inject environment variables and bridge legacy config keys."""
    env_map = {
        "PIHOLE_PASSWORD": ("pihole", "password"),
        "UNIFI_API_KEY": ("unifi", "api_key"),
        "PLEX_TOKEN": ("plex", "token"),
        "SENTINEL_API_KEY": ("server", "api_key"),
        "OPENWEBUI_API_KEY": ("agent", "api_key"),
    }
    for env_var, (section, key) in env_map.items():
        value = os.environ.get(env_var)
        if value:
            raw.setdefault(section, {})[key] = value

    # Bridge legacy "openwebui" config section into "agent" config.
    # The v0.x config used a top-level "openwebui" key; v1.0 uses "agent".
    owui = raw.get("openwebui")
    if owui and isinstance(owui, dict):
        agent = raw.setdefault("agent", {})

        # URL: build from host+port if agent.url not already set
        if not agent.get("url"):
            host = owui.get("host", "")
            port = owui.get("port", 8080)
            if host:
                agent["url"] = f"http://{host}:{port}"

        # API key
        if not agent.get("api_key") and owui.get("api_key"):
            agent["api_key"] = owui["api_key"]

        # Model
        if not agent.get("model") and owui.get("model"):
            agent["model"] = owui["model"]

        # Timeout
        if not agent.get("timeout_seconds") and owui.get("timeout_seconds"):
            agent["timeout_seconds"] = owui["timeout_seconds"]

        # Auto-enable agent when we have a URL and model (bridged from legacy config)
        if agent.get("url") and agent.get("model") and "enabled" not in agent:
            agent["enabled"] = True
            import logging as _logging
            _logging.getLogger(__name__).info(
                "Agent auto-enabled via legacy 'openwebui' config section (url=%s, model=%s)",
                agent.get("url"), agent.get("model"),
            )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_settings: Optional[Settings] = None


def get_settings(config_path: str | None = None) -> Settings:
    global _settings
    if _settings is None:
        if config_path is None:
            config_path = os.environ.get("CONFIG_PATH", "config.yaml")
        _settings = Settings.from_yaml(config_path)
    return _settings


def reload_settings(config_path: str | None = None) -> Settings:
    global _settings
    if config_path is None:
        config_path = os.environ.get("CONFIG_PATH", "config.yaml")
    _settings = Settings.from_yaml(config_path)
    return _settings
