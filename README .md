# ZeroCore Agent

> **Automated Incident Response Agent** — File integrity monitoring, active IP blocking, and structured event telemetry with a REST API for SOC integration.

[![CI](https://github.com/yourorg/zerocore-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/yourorg/zerocore-agent/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)

---

## What It Does

ZeroCore Agent is a lightweight, host-deployed security daemon that:

- **Monitors** critical filesystem paths (FIM) using inotify-based watchdog with SHA-256 baseline comparison
- **Detects** unauthorized modifications, creations, and deletions with severity classification based on path type
- **Responds** automatically by injecting iptables DROP rules for high/critical-severity source IPs — with per-IP cooldown and global rate limiting to prevent self-DoS
- **Persists** all events and mitigation actions to SQLite (WAL mode, indexed)
- **Exposes** a structured REST API for SOC dashboards, SIEM forwarding, and operator tooling
- **Emits** JSON-structured logs compatible with Splunk, Elastic, and Loki

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  ZeroCore Agent                     │
│                                                     │
│  ┌──────────────┐    ┌───────────────────────────┐  │
│  │     FIM      │───▶│       Event Bus           │  │
│  │  (watchdog   │    │  (async pub/sub)          │  │
│  │  + SHA-256)  │    └──────────┬────────────────┘  │
│  └──────────────┘               │                   │
│                          ┌──────▼──────┐            │
│                          │  Active     │            │
│                          │  Response   │            │
│                          │  Engine     │            │
│                          │  (rate      │            │
│                          │  limited)   │            │
│                          └──────┬──────┘            │
│                                 │                   │
│  ┌──────────────┐    ┌──────────▼──────┐            │
│  │  FastAPI     │    │  Linux Firewall │            │
│  │  REST API    │    │  Manager        │            │
│  │  (auth +     │    │  (CAP_NET_ADMIN │            │
│  │   paginated) │    │   no sudo)      │            │
│  └──────┬───────┘    └─────────────────┘            │
│         │                                           │
│  ┌──────▼───────────────────────────────────────┐   │
│  │         SQLite (WAL, async, indexed)         │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

**Key design decisions:**
- FIM → EventBus → Response Engine are fully decoupled via async pub/sub
- No sudo anywhere — iptables access via `CAP_NET_ADMIN` process capability
- No in-memory storage — all events/actions persisted to SQLite with WAL
- Secrets loaded exclusively from environment variables — never from YAML or code
- Docs endpoints disabled in production (`ZEROCORE_ENVIRONMENT=production`)

---

## Severity Classification

| Path Pattern | Severity |
|---|---|
| `/boot/`, `/bin/`, `/sbin/`, `/usr/bin/`, `/lib/` | CRITICAL |
| `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/` | HIGH |
| `/etc/` (generic) | MEDIUM |
| All other watched paths | LOW |

SHA-256 hash mismatch on a MEDIUM path **promotes** it to HIGH automatically.

---

## Quick Start

### Prerequisites

- Python 3.12+
- Linux host (iptables required for auto-blocking)
- `CAP_NET_ADMIN` capability for iptables (or Docker `NET_ADMIN`)

### 1. Clone & Configure

```bash
git clone https://github.com/yourorg/zerocore-agent.git
cd zerocore-agent

cp .env.example .env
# Edit .env — set ZEROCORE_SECRET_KEY and ZEROCORE_API_KEY
```

### 2. Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Run

```bash
python -m src.main
```

### 4. Test the API

```bash
# Health check (no auth)
curl http://localhost:8000/health

# Authenticated status
curl -H "X-ZeroCore-API-Key: your_api_key" http://localhost:8000/api/v1/health

# List events
curl -H "X-ZeroCore-API-Key: your_api_key" \
     "http://localhost:8000/api/v1/events?page=1&page_size=20"

# Manual IP block
curl -X POST http://localhost:8000/api/v1/mitigation/block \
     -H "X-ZeroCore-API-Key: your_api_key" \
     -H "Content-Type: application/json" \
     -d '{"ip_address":"10.0.0.1","reason":"Suspicious scan","requested_by":"analyst1"}'
```

---

## Docker

```bash
# Build and run
docker compose up -d

# View structured logs
docker compose logs -f zerocore-agent
```

The compose file mounts `/etc` and `/bin` read-only into the container for monitoring. `CAP_NET_ADMIN` is added for iptables access.

---

## API Reference

All endpoints under `/api/v1/` require `X-ZeroCore-API-Key` header.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Public health probe (no auth) |
| GET | `/api/v1/health` | Agent status, uptime, counters |
| GET | `/api/v1/events` | Paginated security events (filter by severity/type) |
| GET | `/api/v1/actions` | Paginated mitigation actions |
| POST | `/api/v1/mitigation/block` | Manually block an IP |
| POST | `/api/v1/mitigation/unblock` | Manually unblock an IP |
| GET | `/api/v1/baseline` | List all FIM baseline entries |
| POST | `/api/v1/baseline/snapshot` | Trigger a fresh baseline snapshot |

Interactive docs available at `/docs` in development mode.

---

## Testing

```bash
pytest
```

Coverage target: 70% minimum (enforced in CI).

---

## Configuration Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `ZEROCORE_SECRET_KEY` | ✅ | — | JWT signing secret (min 32 chars) |
| `ZEROCORE_API_KEY` | ✅ | — | API authentication key (min 16 chars) |
| `ZEROCORE_ENVIRONMENT` | | `production` | `development`, `staging`, `production` |
| `ZEROCORE_WATCH_PATHS` | | `/etc/passwd,...` | Comma-separated paths to monitor |
| `ZEROCORE_AUTO_BLOCK` | | `true` | Enable automated IP blocking |
| `ZEROCORE_BLOCK_COOLDOWN_SECONDS` | | `60` | Per-IP cooldown between blocks |
| `ZEROCORE_MAX_BLOCKS_PER_MINUTE` | | `10` | Global auto-block rate cap |
| `ZEROCORE_DB_PATH` | | `data/zerocore.db` | SQLite database path |

See `.env.example` for the full list.

---

## Roadmap

- [ ] eBPF probe integration (libbpf) for syscall-level visibility
- [ ] Sigma rule engine for pattern-based detection
- [ ] gRPC transport for agent-to-server communication
- [ ] Prometheus metrics endpoint (`/metrics`)
- [ ] Kubernetes DaemonSet deployment manifests
- [ ] Grafana dashboard

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
