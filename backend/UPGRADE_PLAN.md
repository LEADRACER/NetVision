# NetVision Backend Upgrade: LETHAL & OBSERVABLE

**Current:** Python 3.13 + FastAPI, SQLite, raw scapy/nmap, basic REST, simple health monitor
**Target:** Production-grade network reconnaissance platform with deep observability, active defense, and autonomous intelligence

---

## PHASE 0 — FOUNDATION (prerequisites, no code changes)

| Action | Rationale |
|--------|-----------|
| Add `alembic` for DB migrations | Schema evolves; raw CREATE TABLE is death |
| Add `.env` + `pydantic-settings` config class | 6 env vars scattered across main.py is fragile |
| Add `logging-config.yaml` (structured JSON) | `print()` calls everywhere — no levels, no structured data |
| Replace `print()` with `structlog` | Every `print("[*] ...")` becomes `log.info("msg", component="scanner", ...)` |

**Already available:** `pydantic-settings`, `loguru`, `alembic` (needs install)

---

## PHASE 1 — OBSERVABILITY (make it OBSERVABLE)

### 1.1 Structured logging (structlog)
- Replace all `print()` calls with `structlog.get_logger()`
- JSON output with timestamps, levels, correlation IDs, component names
- Request middleware that injects `request_id` into every log line and response header (`X-Request-ID`)
- Separate log files by component: `scanner.log`, `health.log`, `probes.log`, `api.log`

### 1.2 Metrics endpoint (`/metrics`)
- Expose Prometheus-compatible `/metrics` endpoint via `prometheus_client`
- Track: request count, latency histograms per route, scan duration, health check results, probe success/failure rate, packet capture rate
- Enable real-time Grafana dashboarding

### 1.3 Health endpoints (deep)
- `GET /health/live` — is the process alive? (simple)
- `GET /health/ready` — are downstream deps ready? (DB reachable, nmap installed, tshark alive)
- `GET /health/scan` — current scan status, queue depth, last scan time

### 1.4 Alerting hooks
- Webhook sender for critical events: device down >3 checks, vulnerability found, scan failure
- Configurable targets: Slack, Discord, Telegram, email
- Rate-limited alert dedup (don't spam on flapping)

### 1.5 Audit trail
- New `audit_log` table + middleware
- Every API call logged: who (if auth), what, when, IP, user-agent
- Scan starts/stops, config changes, report exports

**Dep installs:** `prometheus-client`, `structlog` (or use `loguru` which is already installed)

---

## PHASE 2 — API HARDENING (make it LETHAL)

### 2.1 Auth & access control
- JWT-based auth (`PyJWT` already installed)
- API key support for programmatic access
- Role-based access: `viewer` (read-only), `operator` (scan/capture), `admin` (config/delete)
- Token refresh, revocation, automatic expiry

### 2.2 Rate limiting & DoS protection
- Token-bucket per IP per endpoint group
- Scan endpoint throttled (max 1 concurrent scan per user)
- Request size limits, timeout enforcement on all routes

### 2.3 Input validation hardening
- Replace bare `Optional[str]` params with full `pydantic` models using `Field(..., pattern=...)` for IPs, hosts, ports
- Validate scan targets against private IP ranges (prevent SSRF)
- File upload/download path traversal prevention (already partially done, needs hardening)

### 2.4 CORS & security headers
- CORS origins should be explicit (not `*`)
- Add security headers middleware: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`

---

## PHASE 3 — SCANNER AUTONOMY (make it LETHAL)

### 3.1 Scan queue & task management
- Replace `global is_scanning` + `BackgroundTasks` with proper task queue
- Use `asyncio.Queue` or Redis-backed RQ/Celery (Celery already installed)
- Priority levels: `critical` (top), `high`, `normal`, `low`
- Scheduled/recurring scans (cron-like: scan 192.168.1.0/24 every 4h)
- Scan result diffing (what changed since last scan?)

### 3.2 Advanced scan profiles
| Profile | Args | Use case |
|---------|------|----------|
| `stealth` | `-T1 -sS -n --max-retries 0` | Evasion, IDS avoidance |
| `full` | `-T4 -p- -sV -O` | Comprehensive (all 65535 ports) |
| `vuln` | `-T4 -sV --script vuln,exploit` | Vulnerability hunting |
| `discovery` | `-sn -PS80,443,22` | Quick host discovery |
| `custom` | User-defined NSE args | Power users |

### 3.3 Active vulnerability correlation
- Currently `vulns_detected` is set by keyword match on `old`/`vulnerable`/`beta` — amateur
- Replace with: version-to-CVE lookup via local CVE DB or online API (NVD/NIST)
- CVSS scoring, severity classification, exploitability assessment
- Store in `vulnerabilities` table (schema already exists but is unused)

### 3.4 Autonomous re-scan logic
- If a device goes down in health monitor → auto re-scan that IP
- If new open ports detected → auto probe with service fingerprinting
- If CVE severity > 7.0 → auto alert + detailed probe

---

## PHASE 4 — PACKET CAPTURE & ANALYSIS (make it LETHAL)

### 4.1 Enhanced packet capture
- Current: `tshark -a duration:N -H` → dumps raw pcap
- Upgrade: streaming capture with real-time protocol parsing
- Track per-IP: total packets, bytes, protocols, top talkers
- Detect: ARP spoofing, SYN flood, port scan attempts, DNS tunneling

### 4.2 Protocol decoding
- HTTP request/response capture
- DNS query logging
- TLS handshake metadata (cipher suites, versions, cert info)
- DHCP fingerprinting

### 4.3 Network behavioral analysis
- Baseline normal traffic patterns per device
- Flag anomalies: unexpected protocols, unusual traffic volumes, new device connections
- Store behavioral baselines in DB per MAC address

### 4.4 Deauth / rogue AP detection
- Monitor for deauthentication packets (Wi-Fi)
- Detect beacon frames from unknown SSIDs
- Alert on MAC spoofing (MAC → vendor mismatch)

---

## PHASE 5 — DATABASE & PERSISTENCE (foundation upgrade)

### 5.1 SQLite → production DB prep
- Add WAL mode + proper journaling (SQLite is fine for single-user, but needs tuning)
- Connection pooling (aiosqlite already installed)
- Proper foreign key enforcement (`PRAGMA foreign_keys = ON`)

### 5.2 Schema migrations with Alembic
- Track schema changes properly
- Add indexes on: `devices.ip`, `health_metrics.timestamp`, `scans.started_at`

### 5.3 Data retention policies
- Auto-prune health metrics older than 90 days
- Auto-prune captures older than 7 days
- Configurable TTLs per data type

---

## PHASE 6 — WEBSOCKET & REAL-TIME (observability UX)

### 6.1 WebSocket resilience
- Current: reconnect not handled, no heartbeat, all-or-nothing broadcast
- Add: ping/pong heartbeat (30s interval)
- Add: per-client message queues (slow client doesn't block fast clients)
- Add: reconnection with state sync (send missed updates on reconnect)

### 6.2 Event streams
- `scan.progress` — chunk results as they come in
- `health.alert` — device goes up/down
- `vuln.found` — new vulnerability discovered
- `capture.data` — live packet stats

---

## PHASE 7 — INFRASTRUCTURE & RELIABILITY

### 7.1 Graceful shutdown
- Current: health monitor cancel on shutdown (good start)
- Need: drain active scans, flush metrics, close DB connections properly

### 7.2 Dockerization
- Multi-stage Dockerfile (builder + runtime)
- `docker-compose.yml` with: netvision-api, redis (optional), prometheus + grafana (optional)

### 7.3 Startup probes & init checks
- Verify nmap installation + version
- Verify tshark installation + interface availability
- Verify DB is writable
- Pre-warm geo cache

---

## TARGET INSTALLS

```
# Core observability
pip install prometheus-client structlog

# Database & migration
pip install alembic aiosqlite

# Task queue (optional)
pip install redis[hiredis]

# Docker (system-level)
apt install docker.io docker-compose-v2
```

Many deps already present: `loguru`, `httpx`, `tenacity`, `celery`, `redis`, `aiosqlite`, `bcrypt`, `PyJWT`, `pydantic-settings`, `python-multipart`, `pandas`, `numpy`, `SQLAlchemy`

---

## EXECUTION ORDER

```
Week 1: Phase 0 + Phase 1 (observability foundation) → measurable improvement immediately
Week 2: Phase 2 (API hardening) + Phase 5 (DB upgrade)
Week 3: Phase 3 (scanner autonomy) → the big lethality jump
Week 4: Phase 4 + Phase 6 (packet analysis + real-time)
Week 5: Phase 7 (infrastructure) + integration testing
```

---

## THE "INSTANT FIRE" CHECKLIST

Before/after each phase, these must always pass:
- [ ] `GET /health` returns 200
- [ ] All 20+ REST endpoints return proper HTTP codes
- [ ] WebSocket connects and broadcasts
- [ ] Frontend builds without errors (581ms baseline)
- [ ] Backend starts in <2s with no import errors
- [ ] Health monitor runs without raw socket exceptions
