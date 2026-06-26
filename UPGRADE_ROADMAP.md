# NetVision — Post-7 Upgrade Roadmap

**Codebase:** 26 Python (8K lines) + 16 JSX (1.9K lines) + 13 config/docs files  
**Current state:** Fully delivered Phases 0–7 — observability, auth, scanner autonomy, capture/analysis, DB hardening, WebSocket real-time, Dockerization, dashboard frontend

---

## PHASE 8 — TESTING & QUALITY (foundation debt)

### 8.1 Unit test suite
| Action | Why |
|--------|-----|
| `pytest` with `pytest-asyncio`, `pytest-cov` | Zero tests exist beyond `test_auth.py` — this is the biggest risk |
| Test all 26 backend modules: database CRUD mock, scanner profiles, CVE correlation, packet analysis, WebSocket manager, rate limiter, auth flows | Each module has failure modes that are invisible until runtime |
| Snapshot testing for `/health/*` and `/scan/history` shapes | Schema changes break API contracts silently |
| Property-based tests for IP/port validation (Hypothesis) | Input validation edge cases caught exhaustively |

### 8.2 Integration & E2E tests
| Action | Why |
|--------|-----|
| `docker compose up` → health probes → scan target → verify DB | Validate full pipeline in CI |
| WebSocket E2E: connect → subscribe → trigger scan → verify event receipt | Core real-time contract |
| Auth matrix: all 4 roles × every endpoint combination | RBAC leaks are silent data exposure |

### 8.3 Linting & static analysis
| Action | Why |
|--------|-----|
| `mypy` (strict) across all backend Python | Zero type coverage — `Any` everywhere hides bugs |
| `ruff` + `pyright` in pre-commit | Catch undefined variables, wrong return types |
| Frontend: `eslint` with `typescript-eslint` | JSX has no type checking at all |
| `bandit` security scan on Python | Detect hardcoded secrets, eval(), SQL injection paths |

### 8.4 CI/CD pipeline
| Action | Why |
|--------|-----|
| GitHub Actions: lint → typecheck → test → build → docker | No automation — every deploy is manual |
| Pre-commit hook: ruff + mypy + eslint | Catch before commit |
| Git hooks for `.env` validation | `JWT_SECRET=default` in prod is instant compromise |

---

## PHASE 9 — DATABASE & PERSISTENCE UPGRADE

### 9.1 PostgreSQL migration
| Action | Why |
|--------|-----|
| Replace raw `sqlite3.connect()` with async `SQLAlchemy 2.0` + `asyncpg` | SQLite chokes on concurrent writes from WebSocket + scanner + health monitor |
| Connection pooling via `asyncpg` pool | Current: every request opens/closes a connection |
| Full-text search on CVE descriptions, HTTP logs, DNS queries | PostgreSQL FTS vs current `LIKE '%foo%'` |
| Row-level timestamps with `clock_timestamp()` | Consistent ordering across concurrent sessions |

### 9.2 Alembic → production workflow
| Action | Why |
|--------|-----|
| Auto-generate migrations from SQLAlchemy models | Current: manual SQL in migration files |
| Migration CI check: `alembic check` in CI | Drift between dev/prod schemas goes undetected |
| Rollback testing: each migration must have `downgrade()` | One bad migration = manual restore today |

### 9.3 Data archival & backup
| Action | Why |
|--------|-----|
| Automated daily backup to `/mnt/alex-hdd/netvision-backups/` | Full HDD available — zero protection now |
| WAL checkpoint before backup for consistency | No point-in-time guarantee |
| S3/cloud archival for captures older than 30 days | Local captures consume /root space |
| Prune to cold storage policy: health → 90d, audit → 180d, captures → 7d hot / 90d cold | Already designed in config, not wired to any storage backend |

---

## PHASE 10 — FRONTEND EVOLUTION

### 10.1 Wire orphaned components into navigation
| Action | Why |
|--------|-----|
| Add Security panel as new nav route | Sibling subagent built SecurityPanel.jsx — unreachable |
| Add Queue panel page | QueuePanel.jsx exists, not connected |
| Add Schedules page (recurring scan management) | SchedulesPanel.jsx exists, backend fully supports it |
| Add StreamCapture controls page | StreamCapturePanel.jsx exists, API endpoints complete |
| Add Topology visualization (force-graph) | `react-force-graph-2d` already installed |
| Add Correlation page | Correlation endpoint exists at `/correlation` |

### 10.2 TypeScript migration
| Action | Why |
|--------|-----|
| Rename `.jsx` → `.tsx`, add TypeScript types for all API responses | Every API call returns `any` — typo in field name = silent undefined |
| Generate types from FastAPI OpenAPI schema (`openapi-typescript`) | Source of truth: backend defines, frontend consumes |
| Type-safe WebSocket event dispatch | Wrong event type = runtime error, not compile-time |

### 10.3 Real-time charts & history
| Action | Why |
|--------|-----|
| Time-series chart for health metrics (latency, packet loss over 24h) | `recharts` already installed, `/health/history` endpoint exists |
| Scan duration trend chart | `/scan/history` returns timestamps |
| Packet capture rate over time (line chart) | `capture.data` WebSocket events have packet counts |
| CVE discovery timeline | `/vulnerabilities` has `discovered_at` |
| Network throughput gauge (live) | Top talker data streaming over WebSocket |

### 10.4 Mobile & responsive
| Action | Why |
|--------|-----|
| Collapsed sidebar → bottom nav on mobile | Current sidebar is 240px fixed — unusable on phone |
| Responsive grid: `grid-cols-1` on mobile, `grid-cols-3` on desktop | Dashboard cards stack on narrow screens |
| Touch-friendly controls: larger tap targets, swipe gestures | Scan start/stop is a tiny button today |

### 10.5 PWA & offline
| Action | Why |
|--------|-----|
| Service worker + `manifest.json` | SPA loads fast even on reconnect |
| Cache last-known device list and CVE data in IndexedDB | Dashboard is useful even when backend is down |
| Push notifications for critical alerts | WebSocket works in foreground only today |

---

## PHASE 11 — ADVANCED ANALYTICS & THREAT INTEL

### 11.1 Dark web / threat intel integration
| Action | Why |
|--------|-----|
| Automate threat intel feeds: AlienVault OTX, MISP, Tor node lists,已知恶意IP段 | CVE correlation is good, context is better |
| Cross-reference discovered IPs against known malicious lists | Auto-flag devices communicating with C2 infrastructure |
| Integrate with Hermes dark-web-hacking-fundamentals skill | Tor/I2P/Freenet scanning from Bob/VPN node |
| STIX/TAXII feed ingestion for IoC matching | Industry standard — network traffic matched against published indicators |

### 11.2 ML-based anomaly detection
| Action | Why |
|--------|-----|
| Replace z-score threshold with Isolation Forest / One-Class SVM | Current: hardcoded z > 3 triggers — high false positive rate |
| Traffic baseline seasonal decomposition (hour-of-day, day-of-week) | Weekday traffic != weekend traffic — current model assumes stationarity |
| Auto-encoder on protocol distributions for zero-day beaconing detection | `traffic_baseline.py` stores protocol mix — ideal feature vector |
| Model persistence + versioning (MLflow / ONNX) | MlOps stack is already in the environment |

### 11.3 Geo-political risk scoring
| Action | Why |
|--------|-----|
| Enrich every IP with geo + ASN + risk tier | Already have `geolocation.py` — extend to score |
| Score devices based on: geolocation risk, open ports, CVE count, traffic anomalies | Aggregate → single `risk_score` per device |
| Alert when a device crosses risk threshold | Current: no risk model at all |

### 11.4 Automated response playbooks
| Action | Why |
|--------|-----|
| Device down >3 checks → auto-enqueue quick scan ✅ DONE | Keep this pattern, extend to other triggers |
| Critical CVE found → auto-block IP via iptables/nftables | Currently: alert only, no action |
| Rogue AP detected → auto-deauth + alert + block BSSID | Currently: detect + alert, no remediation |
| SYN flood threshold crossed → rate-limit offending IP via tc/iptables | Proactive defense, not just observability |

---

## PHASE 12 — INFRASTRUCTURE & DEVOPS

### 12.1 Monitoring stack activation
| Action | Why |
|--------|-----|
| `docker compose --profile monitoring up -d` | Prometheus + Grafana already configured — just need to run it |
| Grafana dashboard JSON: NetVision overview panel | Pre-built dashboard with device counts, scan throughput, alert rate |
| Alert rules in Prometheus (CPU > 80%, scan failures > 3, DB size > 1GB) | Currently: no server-level alerts |
| Loki log aggregation → Grafana | Structured JSON logs are ready — no log viewer exists |

### 12.2 Performance benchmarking
| Action | Why |
|--------|-----|
| Load test: `locust` or `k6` on `/devices`, `/scan/history`, `/capture/analysis-summary` | No idea what the breaking point is |
| WebSocket concurrent client test (100 clients) | `websocket_manager.py` has per-client queues — need to verify they don't OOM |
| Scan timing benchmark: each profile (quick/stealth/full/vuln) × subnet size | No SLA on scan completion times |

### 12.3 Security hardening
| Action | Why |
|--------|-----|
| Production TLS via Caddy reverse proxy in docker-compose | Currently: HTTP only |
| `Content-Security-Policy` header hardening | Lax CSP allows XSS in dashboard |
| Rate limiter → Redis-backed (persistent across restarts) | In-memory counters reset on restart → attacker can retry immediately |
| Secret rotation: `JWT_SECRET` must be rotated via endpoint, not config change | No secret rotation capability at all |
| Audit log forwarding to external SIEM (syslog / HTTP) | Audit trail is local-only today |

### 12.4 Database administration UI
| Action | Why |
|--------|-----|
| Adminer or pgAdmin in docker-compose (profiled) | Raw SQLite CLI is the only way to inspect data today |
| Data browser page in the dashboard (read-only SQL console) | Operator convenience without SSH access |
| One-click DB export (CSV/JSON) from dashboard | Report generation exists in `reports.py` but no UI trigger |

---

## PHASE 13 — ECOSYSTEM & INTEGRATION

### 13.1 Hermes integration
| Action | Why |
|--------|-----|
| NetVision skill for Hermes: "scan network 192.168.1.0/24" → triggers API → returns results | Voice/chat-driven network recon |
| Telegram gateway: receive alerts, trigger scans, query device status | Currently: Slack/Discord/Telegram alert outbound, no inbound commands |
| Cron-based recurring scan via Hermes cron system | Scheduled scans exist in backend but need external scheduler to trigger |

### 13.2 Multi-node deployment
| Action | Why |
|--------|-----|
| Agent-sensor architecture: multiple capture agents → central server | One machine can't monitor a /16 subnet with full packet capture |
| Redis pub/sub for cross-node event distribution | WebSocket currently local-only |
| Distributed task queue (Redis-backed `arq` or `celery`) | Priority queue is in-memory, lost on restart |

### 13.3 API ecosystem
| Action | Why |
|--------|-----|
| OpenAPI 3.1 with full request/response examples | `/docs` is auto-generated but has zero descriptions |
| Rate-limited public API keys (daily quota, IP whitelist) | API keys exist but have no rate limits per key |
| Webhook registrations: user registers a URL to receive scan.complete/capture.alert | Currently: fixed webhook targets only |
| SDK: Python `netvision-sdk` package on PyPI | Programmatic access from external tools |

---

## EXECUTION ORDER (recommended)

```
Week 1-2:  Phase 8 (testing) — can't refactor safely without tests
Week 3:    Phase 10.1 (wire orphaned frontend panels) — quick wins, visible progress
Week 4:    Phase 12.1 (monitoring stack) — infra visibility
Week 5-6:  Phase 9 (PostgreSQL migration) — biggest architectural impact
Week 7-8:  Phase 10.2-10.3 (TypeScript + charts) — solidify frontend
Week 9-10: Phase 11 (threat intel + anomaly ML) — the "lethality" upgrade
Week 11:   Phase 12.2-12.3 (benchmarking + security hardening)
Week 12:   Phase 13 (ecosystem integration)
```

---

## LOW-HANGING FRUIT (can ship in a single session)

These require minimal effort but deliver high value:

| Task | Effort | Impact |
|------|--------|--------|
| Wire SecurityPanel, QueuePanel, SchedulesPanel into nav | ~30 min | 3 new functional pages instantly |
| Add `/health/history` time-series chart to Overview | ~45 min | First historical visualization |
| `docker compose --profile monitoring up` | ~2 min | Full Prometheus + Grafana stack |
| Grafana dashboard with NetVision metrics | ~1 hr | Professional observability |
| TypeScript the `api.js` return types | ~30 min | Catch field-name typos at compile time |
| Add backup cron to HDD | ~15 min | First data protection |
| Wire `require_role` on remaining unprotected endpoints | ~20 min | Close auth gaps |
| Run `npx vite build` in CI | ~10 min | Catch build failures |
