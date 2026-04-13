# SentinelHome — Deployment Guide

## Overview

SentinelHome runs as a single Docker container with host networking. It needs:
- **Syslog data** — from your router, APs, or switches (UDP or mounted log files)
- **A data directory** — for the SQLite database, config, and logs
- **(Optional) An LLM backend** — Open WebUI proxying to llama.cpp or Ollama on a GPU

```
┌────────────────────────────┐         ┌──────────────────────────┐
│  Server (always-on)        │  HTTP   │  GPU Host (optional)     │
│                            │◄───────►│                          │
│  SentinelHome :8890        │         │  llama.cpp / Ollama      │
│  (Docker, host networking) │         │  Open WebUI :8084        │
│                            │         │  (chat, tools, RAG)      │
└──────────┬─────────────────┘         └──────────────────────────┘
           │
    Syslog (UDP 514 or file mount)
           │
┌──────────┴─────────────────┐
│  Network devices           │
│  Router, APs, switches     │
└────────────────────────────┘
```

The GPU host can be the same machine or a separate box on the LAN. Open WebUI can run anywhere that can reach both the LLM backend and SentinelHome's API.

---

## Part 1: SentinelHome Container

### 1.1 Docker Run

```bash
docker run -d \
  --name sentinel-home \
  --restart unless-stopped \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --network host \
  -v /path/to/syslog:/mnt/syslog:ro \
  -v /path/to/data:/data \
  -e SENTINEL_API_KEY=choose_a_key \
  -e OPENWEBUI_API_KEY=your_openwebui_key \
  -e UNIFI_API_KEY=your_unifi_integration_key \
  ghcr.io/user/sentinel-home:latest
```

**Why `--network host`**: Scapy needs direct access to the LAN interface for passive sniffing. Without host networking, the container can't see ARP, mDNS, or DHCP traffic.

**Why `NET_RAW` + `NET_ADMIN`**: Required for Scapy's raw socket capture. These are the minimum capabilities needed — do not use `--privileged`.

### 1.2 Volume Mounts

| Host Path | Container Path | Mode | Purpose |
|-----------|----------------|------|---------|
| Syslog directory | `/mnt/syslog` | `ro` | Per-device syslog files (e.g. `syslog-192.168.1.1.log`) |
| Data directory | `/data` | `rw` | SQLite DB, config.yaml, rotating logs |

Create the data directory before first run:
```bash
mkdir -p /path/to/data
```

### 1.3 Configuration

Copy `config.yaml.example` to your data directory as `config.yaml`:
```bash
cp config.yaml.example /path/to/data/config.yaml
```

Most settings auto-detect. A minimal config works out of the box. Edit to enable integrations:

```yaml
# Minimal config — everything else auto-detects
unifi:
  enabled: true
  host: "192.168.1.x"       # Your UniFi gateway IP
  # api_key via UNIFI_API_KEY env var

pihole:
  enabled: true
  host: "192.168.1.x"       # Your Pi-hole IP

agent:
  enabled: true
  url: http://192.168.1.x:8084   # Open WebUI URL
  api_key: sk-...
  model: sentinel-analyst
  chat_model: sentinel-chat
  investigator_model: sentinel-investigator
```

Secrets should be environment variables rather than in the config file:
- `SENTINEL_API_KEY` — protects POST endpoints
- `OPENWEBUI_API_KEY` — authenticates to Open WebUI
- `UNIFI_API_KEY` — UniFi Integration API key (see Part 2.5)
- `PIHOLE_PASSWORD` — Pi-hole admin password
- `PLEX_TOKEN` — Plex authentication token

### 1.4 Dockerfile

```dockerfile
FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml .
COPY sentinel_home/ sentinel_home/

RUN pip install --no-cache-dir -e .

EXPOSE 8890
CMD ["sentinel-home"]
```

### 1.5 Database Migrations

SentinelHome uses Alembic for schema migrations. On first run, the database is created automatically. On upgrades:

```bash
# Inside the container or with the venv active:
alembic upgrade head
```

Migrations live in `alembic/versions/`. The database at `/data/sentinel.db` persists across container restarts — your data survives upgrades.

---

## Part 2: Syslog Configuration

SentinelHome accepts syslog two ways. Configure whichever works for your setup:

### Option A: UDP Syslog (preferred)

SentinelHome listens on UDP 514. Point your devices at the host IP.

**Requires**: The container must run as root or have `NET_ADMIN` to bind port 514. If binding fails (common in rootless Docker), it falls back to file mode automatically.

**UniFi**: Settings → System → Advanced → Remote Syslog → set host IP and port 514.

**OpenWrt**: System → Logging → set remote syslog server IP.

**pfSense/OPNsense**: Status → System Logs → Settings → Remote Logging.

### Option B: File-based Syslog

Mount a directory of syslog files. The file tailer watches for changes and processes new lines. Files should be named `syslog-{IP}.log` (e.g. `syslog-192.168.1.1.log`).

This works well when your server already runs rsyslog and writes per-device files:

```
# rsyslog template for per-source-IP files:
template(name="PerHostFile" type="string"
         string="/path/to/syslog/syslog-%FROMHOST-IP%.log")
if $fromhost-ip != '127.0.0.1' then ?PerHostFile
& stop
```

### Parser Auto-Detection

SentinelHome's parser chain tries all registered parsers against each line. No manual device-type mapping is needed — iptables logs, hostapd events, UniFi JSON, and dnsmasq output are all recognized automatically.

Available parsers:
- **iptables** — Firewall block/accept from any Linux router (iptables, nftables, UFW)
- **hostapd** — WiFi authentication, association, WPA handshake events
- **unifi** — STA_TRACKER JSON, wevent client events, switch provisioning
- **dnsmasq** — DHCP leases and DNS query logs (OpenWrt, Pi-hole)
- **unraid** — Disk health, emhttpd, mover, Docker crash events
- **syslog_header** — RFC 3164/5424 header extraction for any source

---

## Part 2.5: UniFi Network Integration (Optional)

If you have a UniFi gateway (Dream Machine, Express, Cloud Gateway), SentinelHome can poll the Integration API for rich client/device data, infrastructure health metrics, and network topology.

### Setup

1. **Create an Integration API key** in the UniFi Network UI:
   - Settings → Control Plane → Integrations → Create Integration
   - Copy the generated API key

2. **Set the environment variable**:
   ```bash
   UNIFI_API_KEY=your_key_here
   ```

3. **Enable in config.yaml**:
   ```yaml
   unifi:
     enabled: true
     host: "192.168.1.1"          # Your UniFi gateway IP
     poll_interval_seconds: 60     # Client/device polling interval
     # verify_ssl: false           # Self-signed certs on most gateways
   ```

### What it collects

| Data | Interval | What it does |
|------|----------|-------------|
| **Clients** | Every 60s | WiFi signal strength, channel, band, AP association, VLAN, connect/disconnect events |
| **Devices** | Every 60s | Infrastructure state (online/offline), device type, firmware version |
| **Device stats** | Every 5 min | CPU load, memory %, uplink throughput, radio TX retries, client count → `infra_metrics` table |
| **VLANs & SSIDs** | Every 30 min | Network topology stored as baselines, change detection fires rules |
| **Firewall config** | Every 30 min | Zone/policy configuration stored as baselines |

### Write actions (via chat)

When chatting with the model in Open WebUI, it can execute UniFi actions on your behalf:

- **Block/unblock client** — quarantine a suspicious device
- **Reconnect client** — force a WiFi client to reassociate
- **Restart device** — reboot an AP or switch

All write actions are audit-logged as events and notes. The model explains what it's doing and why.

### New detection rules

The UniFi collector enables 7 additional rules (20 total):

| Rule | Severity | Trigger |
|------|----------|---------|
| `infra_device_offline` | high | Infrastructure device goes offline |
| `infra_high_cpu` | medium | CPU load >80% (5-min average) |
| `infra_high_memory` | medium | Memory usage >90% |
| `ap_high_retries` | medium | WiFi TX retry rate >15% |
| `ssid_config_change` | high | SSID configuration changed |
| `firewall_policy_change` | high | Firewall rules changed |
| `vpn_client_connect` | info | VPN/Teleport client connected |

### API endpoints

Infrastructure data is available through the REST API:

- `GET /api/v1/infrastructure` — all infra devices with latest metrics
- `GET /api/v1/infrastructure/health` — summary with warning indicators
- `GET /api/v1/infrastructure/{mac}/metrics?hours=24` — time-series metrics
- `GET /api/v1/network/vlans` — cached VLAN configuration
- `GET /api/v1/network/ssids` — cached WiFi SSID configuration
- `GET /api/v1/network/firewall` — cached firewall zones and policies
- `POST /api/v1/unifi/action` — execute a UniFi write action (audit-logged)

---

## Part 3: Open WebUI + LLM Setup

This is optional. SentinelHome works fully without an LLM — you get the dashboard, rules, notifications, and all data collection. The LLM adds conversational analysis, automated triage, and rule tuning.

See [deploy/README.md](deploy/README.md) for the complete setup guide covering:
1. **LLM server** — llama.cpp or Ollama on a GPU machine
2. **Open WebUI** — Model profiles, tools, and knowledge collection
3. **SentinelHome config** — Connecting the agent to Open WebUI

### Open WebUI Configuration (v0.8.11+)

After installing Open WebUI, configure these settings for optimal SentinelHome integration:

**Retrieval/RAG settings** (Admin → Settings → Documents):
- Enable **Hybrid Search** for combined keyword + semantic retrieval
- Set reranking model to `BAAI/bge-reranker-v2-m3` for improved result quality
- Knowledge search scoping ensures the model only retrieves from relevant collections

**Model capabilities** (per model profile):
- Enable `memory` capability so the model remembers facts across conversations
- The setup script configures this automatically for the `sentinel-chat` profile

**Tool HTML embeds** (v0.8.8+):
- Infrastructure health, network topology, and firewall summary tools return rich HTML cards
- These render inline in the chat as visual status displays alongside text context for the model

### Quick Summary

```bash
# 1. Start llama.cpp on your GPU machine
#    Edit deploy/llama-server.bat (Windows) or deploy/llama-server.sh (Linux/macOS)

# 2. Set up Open WebUI model profiles + tool + knowledge
uv run python scripts/setup_openwebui_models.py \
    --url http://OPENWEBUI_IP:8084 \
    --api-key sk-... \
    --base-model "your-model-name"

# 3. Configure Tool Valves in Open WebUI UI
#    Tools → SentinelHome → gear icon → set sentinel_url and api_key

# 4. Enable the agent in config.yaml
agent:
  enabled: true
  url: http://OPENWEBUI_IP:8084
  model: sentinel-analyst
```

---

## Part 4: Passive Sniffing

Scapy captures on the host's LAN interface. The interface is auto-detected, but can be overridden:

```yaml
network:
  sniff_interface: eth0   # default: auto-detect
```

**What it captures** (all passive, no packets sent):
- ARP announcements → device discovery, conflict detection
- mDNS advertisements → service names, device types
- DHCP requests → hostname, vendor class
- UPnP SSDP → device descriptions, port mappings
- SMB traffic → file sharing detection

On startup, there's a 120-second warmup period where ARP events are learned without generating alerts.

---

## Part 4.5: Dashboard Authentication

By default the dashboard is open — no login required. This is fine for a home LAN where you trust everyone on the network.

To password-protect the dashboard:

1. Open the dashboard at `http://YOUR_IP:8890/settings`
2. Scroll to the **Authentication** card
3. Click **Set Password** and enter a password (minimum 4 characters)

Once set, all dashboard pages redirect to `/login`. The session cookie expires when the browser closes. To remove the password, use the API:

```bash
curl -X DELETE http://YOUR_IP:8890/api/v1/auth/password \
  -H "X-API-Key: your_sentinel_api_key"
```

**Note**: The REST API (`/api/v1/...`) is not affected by dashboard auth — it uses the `X-API-Key` header independently. The auth middleware only protects the dashboard UI routes.

---

## Part 5: Notifications

SentinelHome uses [Apprise](https://github.com/caronc/apprise) for notifications. Supports 80+ services.

```yaml
notifications:
  urls:
    - "tgram://bottoken/ChatID"       # Telegram
    - "ntfy://ntfy.sh/my-sentinel"    # ntfy
    - "slack://TokenA/TokenB/TokenC"  # Slack
    - "mailto://user:pass@gmail.com"  # Email
    - "discord://WebhookID/Token"     # Discord
  min_severity: high                  # Only notify on high/critical
```

Notifications fire when rules create alerts. Each notification includes the rule name, severity, device involved, and a summary message.

---

## Part 6: First-Run Checklist

After deploying the container:

```bash
# 1. Dashboard is up
open http://YOUR_IP:8890

# 2. API health
curl http://YOUR_IP:8890/api/v1/status

# 3. Devices appearing (populated from syslog + ARP + nmap)
curl http://YOUR_IP:8890/api/v1/devices

# 4. Rules loaded
curl http://YOUR_IP:8890/api/v1/rules

# 5. (If agent enabled) LLM reachable
# Check the live logs page — should show "LLM completions path: ... (HTTP 200)"
```

**What to expect in the first hour:**
- ARP warmup (2 min) → devices start appearing
- First nmap scan → port inventory populated
- Syslog events flowing → event counts on dashboard
- UniFi polling (if enabled) → client WiFi details, infrastructure metrics, network topology
- Pi-hole polling (if enabled) → DNS query stats
- Agent actor cycle (if enabled) → first triage at ~30 seconds, then every 15 min

---

## Part 7: Upgrades

```bash
docker pull ghcr.io/user/sentinel-home:latest
docker stop sentinel-home && docker rm sentinel-home
# Re-run with same flags as Part 1
```

The SQLite database persists at `/data/sentinel.db`. Alembic migrations run automatically on startup.

**Important**: Do not delete the `/data` volume — it contains your database, config, and logs.
