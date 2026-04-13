# SentinelHome

**Home network security & health monitor.** Single Docker container. Works with any router that sends syslog. Optional LLM-powered analysis via Open WebUI.

## What it does

SentinelHome monitors your home network, categorizes events, detects anomalies, and presents everything through a real-time dashboard. It's primarily passive and read-only — with optional UniFi write actions (block/unblock clients, restart devices) available through the chat interface when explicitly requested.

### Data Collection

- **Syslog ingestion** — UDP listener or file-based tailing from routers, APs, switches
- **Passive sniffing** — ARP monitoring, mDNS discovery, DHCP fingerprinting, UPnP detection via Scapy
- **Port scanning** — Periodic nmap scans with diff detection (new open ports → findings)
- **UniFi Network API** — Client/device inventory, WiFi signal metrics, infrastructure health, network topology, firewall config
- **DNS monitoring** — Pi-hole integration for query logging and DGA detection
- **Media tracking** — Plex integration for remote access session detection

### Analysis & Detection

- **20 built-in rules** — Unknown devices, deauth storms, port scan detection, WAN attack patterns, DNS anomalies, infrastructure health, config change detection
- **ECS-compatible events** — Categorized, aggregated, with configurable retention
- **Device inventory** — Auto-discovered with OUI vendor lookup, type classification, network role
- **Metrics & rollups** — Hourly aggregation, pre-computed dashboard stats, WAN block counters
- **Threat intelligence** — Free lists (Firehol, Spamhaus, Emerging Threats) fetched locally

### Dashboard & Interaction

- **Real-time web UI** — HTMX + Alpine.js dashboard with device inventory, event browser, WAN heatmap
- **Notes & annotations** — Add context to any entity (devices, rules, events, findings)
- **Inline editing** — Click-to-edit device labels, types, roles, and service descriptions
- **Live logs** — SSE-streamed application logs with filtering
- **Notifications** — Apprise-based alerts (Telegram, ntfy, email, Discord, 80+ services)

### LLM Integration (Optional)

- **Open WebUI as infrastructure** — Chat history, RAG, memory, tools, and functions
- **Actor-critic agent** — Actor triages events every 15 min, critic evaluates rules every 12 hours
- **Dashboard chat** — Ask questions about your network directly from the UI
- **Tool calling** — 22 API functions the model can call during conversations (including HTML-embedded status views and UniFi write actions)
- **Knowledge sync** — Network state pushed to Open WebUI RAG every 5 minutes
- **Consensus for changes** — Rule modifications require two agreeing LLM responses

## Architecture

```
  Syslog (UDP/file) ──► Parser Chain ──► Event Pipeline ──► SQLite
  Scapy (passive)   ──►  (iptables,     (categorize,       │
  nmap (scheduled)  ──►   hostapd,       fingerprint,    ┌──┴──┐
  UniFi API         ──►   dnsmasq,       aggregate,      │ API │──► Dashboard (HTMX)
  Pi-hole API       ──►   unifi,         hard rules)     └──┬──┘     ↕ Notes
  Plex API          ──►   unraid)                           │        ↕ Chat
                                                     ┌─────┴─────┐
                                                     │ Open WebUI │
                                                     │  (optional)│
                                                     │ Tools, RAG │
                                                     │ Chat, Mem  │
                                                     └───────────┘
```

**System 1 (Data Platform)** works standalone — no LLM required. Full dashboard with device inventory, categorized events, WAN security stats, notes, and notifications.

**System 2 (Agent)** is optional. Connect Open WebUI and get AI-powered triage, investigation, rule tuning, and conversational network analysis.

## Quick Start

### 1. Deploy SentinelHome

```bash
docker run -d \
  --name sentinel-home \
  --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v /path/to/syslog:/mnt/syslog:ro \
  -v /path/to/data:/data \
  -e SENTINEL_API_KEY=choose_a_key \
  ghcr.io/user/sentinel-home:latest
```

Copy `config.yaml.example` to your data directory as `config.yaml` and edit it. Most settings auto-detect — a minimal config works out of the box.

Dashboard: `http://your-server:8890`

### 2. Point syslog at SentinelHome

Configure your router/APs/switches to send syslog to the SentinelHome host on UDP 514. If UDP isn't available, mount syslog files into `/mnt/syslog` — the file tailer picks them up automatically.

### 3. (Optional) Set up LLM analysis

See [deploy/README.md](deploy/README.md) for the full Open WebUI + llama.cpp setup guide.

**TL;DR:**

1. Run llama.cpp or Ollama on a GPU machine (e.g. `deploy/llama-server.bat`)
2. Connect Open WebUI to the LLM backend
3. Run `scripts/setup_openwebui_models.py` to create model profiles, install tools, and set up RAG
4. Set `agent.enabled: true` in `config.yaml` with Open WebUI URL

## Supported Infrastructure

**Syslog sources** (UDP 514 or file-based):

- UniFi (Express, Dream Machine, APs, switches)
- OpenWrt
- pfSense / OPNsense
- Any Linux-based router (iptables/nftables logging)

**API integrations:**

- UniFi Network (Integration API v10.1 — clients, devices, stats, topology, firewall, write actions)
- Pi-hole v6 (DNS monitoring)
- Plex Media Server (remote session detection)

**Passive (no config needed):**

- ARP table monitoring (Scapy)
- mDNS service discovery
- DHCP fingerprinting
- UPnP port mapping detection
- nmap port scanning

## Project Structure

```
sentinel_home/
├── agent/              # LLM orchestrator, scheduler, adapter, validator
├── api/routes/         # REST API (devices, events, rules, notes, reports, ...)
├── baseline/           # Behavioral baseline manager
├── collectors/         # Syslog (UDP + file), sniff, nmap, unifi, pihole, plex
├── dashboard/          # HTMX dashboard routes and templates
├── metrics/            # Event counters and hourly rollups
├── notifications/      # Apprise-based alert routing and formatting
├── parsers/            # Syslog parsers: iptables, hostapd, unifi, dnsmasq, unraid
├── queue/              # LLM job queue with compaction
├── rules/              # Detection rule engine and definitions
├── models.py           # SQLAlchemy models (Device, Event, Rule, Note, InfraMetric, ...)
├── config.py           # YAML config loader with env var overrides
├── database.py         # SQLAlchemy session management
└── fingerprint.py      # OUI vendor lookup and device fingerprinting
deploy/                 # Open WebUI tools/functions, llama.cpp scripts
scripts/                # Setup automation
tests/                  # pytest suite (parsers, rules, validator, API, notifications)
alembic/                # Database migrations
```

## Stack

Python 3.13, FastAPI, SQLAlchemy/SQLite, Scapy, APScheduler, HTMX + Alpine.js, Alembic, Apprise

## Configuration

See `config.yaml.example` for all options with comments. Key sections:

| Section | Purpose |
|---------|---------|
| `network` | Sniff interface, LAN CIDR, WAN IP (all auto-detect) |
| `syslog` | UDP port or file directory, auto mode tries both |
| `nmap` | Scan interval, port list, timeout |
| `unifi` | UniFi gateway host, API key, poll interval, SSL verify |
| `pihole` | Pi-hole host and password |
| `plex` | Plex host and token |
| `agent` | Open WebUI URL, models, actor/critic intervals, conservatism |
| `threat_intel` | Free threat list sources and update interval |
| `notifications` | Apprise URLs and minimum severity |
| `retention` | Days to keep events, rollups, findings |
| `server` | Port, API key, DB path, log level |

Secrets can be set via environment variables: `SENTINEL_API_KEY`, `OPENWEBUI_API_KEY`, `UNIFI_API_KEY`, `PIHOLE_PASSWORD`, `PLEX_TOKEN`.

## Documentation

- [CHANGELOG.md](CHANGELOG.md) — Version history and release notes
- [DEPLOY.md](DEPLOY.md) — Full deployment guide with infrastructure setup
- [deploy/README.md](deploy/README.md) — LLM backend and Open WebUI setup
- [SPEC.md](SPEC.md) — Technical specification and design decisions
- [TODO.md](TODO.md) — Roadmap and current status

## License

Unlicense

## AI Disclosure

Made with Claude Code 2026-03-01
