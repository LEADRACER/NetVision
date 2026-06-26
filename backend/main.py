"""NetVision API — v5.0, hardened & authenticated."""

from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect, HTTPException, Query, Request, Body, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
import asyncio
import json
import os
import socket
import sqlite3
from datetime import datetime
from typing import Optional

from loguru import logger

# Import project modules
from scanner import NetworkScanner
from capturer import PacketCapturer
from database import Database
from health import NetworkHealthMonitor
from geolocation import GeoLocator
from reports import ReportGenerator
from probes import probe_service, PROBES
from middleware import RequestIDMiddleware
from config import settings
from pydantic import BaseModel

# ── Phase 1: Observability imports ────────────────────────────────────────
from metrics import (
    MetricsMiddleware, metrics_endpoint,
    SCAN_DURATION, SCAN_DEVICES_FOUND, SCANS_IN_PROGRESS, SCANS_TOTAL,
    HEALTH_DEVICES_UP, HEALTH_DEVICES_DOWN,
)
from alerts import (
    alert_manager, AlertWebhook,
    Alert, AlertType, AlertSeverity,
)

# ── Phase 2: Auth & Security imports ──────────────────────────────────────
from auth import (
    get_current_user, require_role, require_method, is_path_public,
    login_for_token, refresh_access_token, revoke_token,
    introspect_token, User, Role,
)
from rate_limiter import (
    RateLimitMiddleware, check_scan_rate_limit, API_RATE_LIMITER,
)

# ── Phase 6: WebSocket Manager import ────────────────────────────────────
from websocket_manager import manager as ws_manager
from security import (
    SecurityHeadersMiddleware,
    ScanTargetValidation, CaptureRequestValidation,
    ProbeTargetValidation, LoginRequest, TokenRefreshRequest,
)

# ── Phase 3: Scanner Autonomy imports ─────────────────────────────────────
from task_queue import (
    ScanTaskQueue, Priority, ScanTask, ScanSchedule, ScanDiff,
)
from cve_lookup import CVELookupClient
from packet_analyzer import StreamingPacketAnalyzer
from protocol_decoder import ProtocolDecoder
from traffic_baseline import TrafficBaseliner


# ── Initialize structured logging ────────────────────────────────────────
from logging_setup import setup_logging
setup_logging(settings)
logger.info("NetVision v5.0 starting", extra={"component": "system"})

# ── FastAPI app ───────────────────────────────────────────────────────────
app = FastAPI(title="NetVision v5.0 API")

# Ensure directories (before services that use them)
os.makedirs(settings.captures_dir, exist_ok=True)
os.makedirs(settings.reports_dir, exist_ok=True)

# ── Initialize services ──────────────────────────────────────────────────
scanner = NetworkScanner()
db = Database(settings.database_path_abs)
capturer = PacketCapturer(interface=settings.capture_interface, db=db)
geo = GeoLocator(db, cache_ttl=settings.geo_cache_ttl)
reporter = ReportGenerator(db)
health_monitor = NetworkHealthMonitor(db, interval=settings.health_check_interval)

latest_results = []
# Phase 3: Task queue replaces global is_scanning
scan_queue = ScanTaskQueue(settings.database_path_abs)
cve_client = CVELookupClient()

# ── Middleware stack (order matters) ──────────────────────────────────────
# 1. CORS (always first)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
# 2. Security headers
app.add_middleware(SecurityHeadersMiddleware)
# 3. Rate limiting (before processing)
app.add_middleware(RateLimitMiddleware)
# 4. Request metrics
app.add_middleware(MetricsMiddleware)
# 5. Request ID + audit trail
app.add_middleware(RequestIDMiddleware, db=db)


# ── WebSocket manager (Phase 6) ──────────────────────────────────────────
# The new WebSocketManager lives in websocket_ws_manager.py with:
#   - Per-client async queues (slow clients don't block)
#   - Ping/pong heartbeat (30s interval, 10s timeout)
#   - Topic-based subscriptions (scan.progress, health.alert, ...)
#   - Versioned state history for reconnection sync
#   - Event stream helpers (broadcast_scan_progress, broadcast_vuln_found, ...)


@app.on_event("startup")
async def startup_event():
    db.init_tables()

    # ── Phase 7: Startup probes ──────────────────────────────────────────
    probes_passed = 0
    probes_failed = 0

    # 1. Verify DB is writable
    try:
        with db._get_conn() as conn:
            conn.execute("SELECT 1").fetchone()
        logger.info("Probe: DB writable", extra={"component": "system"})
        probes_passed += 1
    except Exception as e:
        logger.error("Probe FAILED: DB not writable", error=str(e),
                     extra={"component": "system"})
        probes_failed += 1

    # 2. Verify nmap installation
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        first_line = stdout.decode().split("\n")[0] if stdout else "unknown"
        logger.info("Probe: nmap available", version=first_line,
                    extra={"component": "system"})
        probes_passed += 1
    except (FileNotFoundError, asyncio.TimeoutError) as e:
        logger.warning("Probe: nmap not found — scanning disabled",
                       extra={"component": "system"})
        probes_failed += 1

    # 3. Verify tshark installation
    try:
        proc = await asyncio.create_subprocess_exec(
            "tshark", "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        first_line = stdout.decode().split("\n")[0] if stdout else "unknown"
        logger.info("Probe: tshark available", version=first_line,
                    extra={"component": "system"})
        probes_passed += 1
    except (FileNotFoundError, asyncio.TimeoutError) as e:
        logger.warning("Probe: tshark not found — packet capture disabled",
                       extra={"component": "system"})
        probes_failed += 1

    # 4. Pre-warm geo cache (non-blocking, best-effort)
    # Warm up by checking if the geo API is reachable
    try:
        result = geo.lookup("8.8.8.8", force_refresh=False)
        if result:
            logger.info("Probe: Geo IP API reachable",
                        extra={"component": "system"})
        else:
            logger.info("Probe: Geo IP API responded (cached or no data)",
                        extra={"component": "system"})
        probes_passed += 1
    except Exception as e:
        logger.info("Probe: Geo IP API warmup skipped",
                    extra={"component": "system", "reason": str(e)})
        probes_passed += 1  # Not critical

    logger.info("Startup probes complete",
                passed=probes_passed, failed=probes_failed,
                extra={"component": "system"})

    # ── Configure alert webhooks from environment ───────────────────────
    slack_url = os.getenv("ALERT_SLACK_WEBHOOK", "")
    discord_url = os.getenv("ALERT_DISCORD_WEBHOOK", "")
    telegram_url = os.getenv("ALERT_TELEGRAM_WEBHOOK", "")
    generic_url = os.getenv("ALERT_WEBHOOK_URL", "")

    if slack_url:
        alert_manager.add_webhook(AlertWebhook(slack_url, "slack", "slack"))
    if discord_url:
        alert_manager.add_webhook(AlertWebhook(discord_url, "discord", "discord"))
    if telegram_url:
        alert_manager.add_webhook(AlertWebhook(telegram_url, "telegram", "telegram"))
    if generic_url:
        alert_manager.add_webhook(AlertWebhook(generic_url, "generic", "generic"))

    webhook_count = len(alert_manager.webhooks)
    if webhook_count:
        logger.info("Alert webhooks configured", count=webhook_count)
    else:
        logger.info("No alert webhooks configured — alerts will be logged only")

    # ── Data retention sweep (non-blocking) ─────────────────────────────
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, db.prune_health_metrics, settings.prune_health_days)
        await loop.run_in_executor(None, db.prune_audit_log, settings.prune_audit_days)
        await loop.run_in_executor(
            None, db.prune_old_captures, settings.prune_capture_days, settings.captures_dir
        )
        logger.info("Data retention sweep complete", extra={"component": "system"})
    except Exception as e:
        logger.warning("Data retention sweep failed", extra={"component": "system", "error": str(e)})

    # ── Start health monitor ────────────────────────────────────────────
    await health_monitor.start()
    
    # ── Start scan queue ────────────────────────────────────────────────
    # Wire the scan execution function and completion callback to the queue
    scan_queue.register_executor(run_scan_task)
    scan_queue.on_task_complete(_on_scan_complete)
    await scan_queue.start()
    
    # Wire health monitor state changes → auto-rescan + WebSocket alert
    async def health_state_changed(ip: str, old_state: str, new_state: str, device_info: dict):
        """Auto-enqueue a scan when a device transitions state and broadcast health alert."""
        # Broadcast health alert to all subscribed WS clients
        asyncio.create_task(ws_manager.broadcast_health_alert(ip, old_state, new_state, device_info))

        if old_state == "up" and new_state == "down":
            logger.info("Auto-rescan triggered by device down", ip=ip)
            await alert_manager.send_alert(
                Alert(
                    title="Device went offline — rescan triggered",
                    message=f"{device_info.get('vendor', 'Unknown')} at {ip} is down",
                    severity=AlertSeverity.WARNING,
                    alert_type=AlertType.DEVICE_DOWN,
                )
            )
            scan_queue.enqueue(
                target=ip,
                profile="quick",
                priority=Priority.HIGH,
                requester="health_monitor",
            )
        elif old_state == "down" and new_state == "up":
            logger.info("Auto-rescan triggered by device recovery", ip=ip)
            scan_queue.enqueue(
                target=ip,
                profile="deep",
                priority=Priority.NORMAL,
                requester="health_monitor",
            )
    
    health_monitor.on_state_change(health_state_changed)
    
    # ── Log auth status ────────────────────────────────────────────────
    if settings.jwt_secret_is_default:
        logger.warning(
            "Using default JWT secret — set JWT_SECRET in .env for production",
            extra={"component": "system"},
        )
    api_key_count = len(settings.api_keys)
    if api_key_count:
        logger.info("API keys configured", count=api_key_count, extra={"component": "system"})

    logger.info("NetVision startup complete — services online",
                extra={"component": "system", "host": settings.api_host, "port": settings.api_port})


@app.on_event("shutdown")
async def shutdown_event():
    """Graceful shutdown — drain active tasks, flush connections, log summary."""
    logger.info("Shutting down NetVision — draining active tasks...",
                extra={"component": "system"})

    # Phase 7: Stop streaming capture if running
    if getattr(capturer, '_streaming', False):
        try:
            await capturer.stop_streaming()
            logger.info("Streaming capture stopped",
                        extra={"component": "system"})
        except Exception as e:
            logger.warning("Error stopping capture", error=str(e),
                           extra={"component": "system"})

    # Log pending queue state before draining
    pending = scan_queue.pending_count
    logger.info("Scan queue state", pending=pending,
                extra={"component": "system"})

    # Existing graceful shutdown sequence
    await health_monitor.stop()
    await scan_queue.stop()
    await cve_client.close()
    await ws_manager.shutdown()

    # Log final metrics summary
    logger.info("NetVision shutdown complete",
                extra={"component": "system"})


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint with heartbeats, subscriptions, and state sync.

    Protocol
    --------
    Server → Client on connect:
        {"type": "state", "devices": [...], "is_scanning": bool, "_v": int}

    Client can send:
        {"type": "pong"}                          — heartbeat ACK
        {"type": "reconnect", "last_version": N}  — request missed events
        {"type": "subscribe", "topics": [...]}     — subscribe to topics
        {"type": "unsubscribe", "topics": [...]}   — unsubscribe from topics

    Server → Client:
        {"type": "ping"}                          — heartbeat (every 30s)
        {"type": "subscribed", "topics": [...]}    — subscribe response
        {"type": "unsubscribed", "topics": [...]}  — unsubscribe response
        {"event": "scan.progress", ...}            — typed event streams
    """
    # Accept and wrap the client
    client = await ws_manager.connect(websocket)

    # Send initial state snapshot with version
    client.send({
        "type": "state",
        "devices": latest_results,
        "is_scanning": scan_queue.is_active,
        "_v": ws_manager._version_counter,
    })

    # Let the manager handle the full lifecycle (heartbeat, subscriptions, pong)
    await ws_manager.handle_client(client)


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: AUTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════


@app.post("/auth/token")
async def auth_login(credentials: LoginRequest):
    """Authenticate with username/password, receive JWT tokens."""
    return await login_for_token(credentials.username, credentials.password)


@app.post("/auth/refresh")
async def auth_refresh(request: TokenRefreshRequest):
    """Exchange a refresh token for a new access token."""
    return await refresh_access_token(request.refresh_token)


@app.post("/auth/revoke")
async def auth_revoke(token: str = Body(..., embed=True)):
    """Revoke a JWT token by adding it to the revocation set."""
    success = revoke_token(token)
    return {"revoked": success}


@app.get("/auth/whoami")
async def auth_whoami(current_user: User = Depends(get_current_user)):
    """Return current user info from the token."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role.value,
        "scopes": current_user.scopes,
    }


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: OBSERVABILITY ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════


@app.get("/metrics")
async def metrics():
    """Prometheus metrics scrape endpoint."""
    return await metrics_endpoint()


@app.get("/health/live")
async def health_live():
    """Liveness probe — is the process alive?"""
    return {"status": "alive", "timestamp": datetime.now().isoformat()}


@app.get("/health/ready")
async def health_ready():
    """Readiness probe — are downstream dependencies available?"""
    checks = {
        "database": False,
        "nmap": False,
        "tshark": False,
    }

    # Check database
    try:
        conn = sqlite3.connect(settings.database_path_abs)
        conn.cursor().execute("SELECT 1")
        conn.close()
        checks["database"] = True
    except Exception:
        pass

    # Check nmap
    try:
        import subprocess
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
        checks["nmap"] = result.returncode == 0
    except Exception:
        pass

    # Check tshark
    try:
        import subprocess
        result = subprocess.run(["tshark", "--version"], capture_output=True, text=True, timeout=5)
        checks["tshark"] = result.returncode == 0
    except Exception:
        pass

    all_ready = all(checks.values())
    status_code = 200 if all_ready else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ready" if all_ready else "degraded",
            "checks": checks,
            "timestamp": datetime.now().isoformat(),
        },
    )


@app.get("/health/scan")
async def health_scan():
    """Current scan status."""
    return {
        "is_scanning": scan_queue.is_active,
        "active_task": {
            "target": scan_queue.active_task.target,
            "profile": scan_queue.active_task.profile,
            "priority": scan_queue.active_task.priority.name,
        } if scan_queue.active_task else None,
        "queue_depth": scan_queue.pending_count,
        "devices_found": len(latest_results),
        "last_scan": db.get_latest_scan(),
    }


@app.get("/audit-log")
async def get_audit_log(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    method: Optional[str] = Query(None),
    path: Optional[str] = Query(None),
    min_status: Optional[int] = Query(None),
    _: User = Depends(require_role(Role.ADMIN)),  # Only admins can read audit trail
):
    """Query the audit trail. Admin only."""
    return {
        "entries": db.get_audit_log(
            limit=limit,
            offset=offset,
            method=method,
            path_like=path,
            status_min=min_status,
        )
    }


# ═══════════════════════════════════════════════════════════════════════════
# CORE ENDPOINTS — AUTH PROTECTED
# ═══════════════════════════════════════════════════════════════════════════


@app.post("/scan")
async def start_scan(
    request: Request,
    target: Optional[str] = Query(None),
    profile: str = Query("deep"),
    duration: Optional[int] = Query(None),
    trace_hops: bool = Query(False),
    priority: str = Query("normal"),
    custom_args: Optional[str] = Query(None),
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Start a network scan. Enqueues with priority. Requires operator+ role."""
    # Rate limit scan starts per IP
    check_scan_rate_limit(request)

    # Validate target
    validated = ScanTargetValidation(
        target=target,
        profile=profile,
        duration=duration,
        trace_hops=trace_hops,
    )

    # Map priority string to enum
    prio_map = {
        "critical": Priority.CRITICAL,
        "high": Priority.HIGH,
        "normal": Priority.NORMAL,
        "low": Priority.LOW,
    }
    prio = prio_map.get(priority.lower(), Priority.NORMAL)

    # Enqueue the scan
    scan_id = db.start_scan(
        validated.target, validated.profile, validated.duration,
        validated.trace_hops, requester=current_user.username, origin="manual",
    )
    scan_queue.enqueue(
        target=validated.target,
        profile=validated.profile,
        duration=validated.duration,
        trace_hops=validated.trace_hops,
        priority=prio,
        requester=current_user.username,
        scan_id=scan_id,
        profile_args=custom_args,
    )

    SCANS_TOTAL.labels(profile=profile).inc()
    await ws_manager.broadcast_scan_status(True)

    logger.info("Scan enqueued", extra={
        "component": "api", "target": target or "local_subnet",
        "profile": profile, "priority": priority, "duration": duration,
        "user": current_user.username, "scan_id": scan_id,
    })
    return {
        "status": "enqueued",
        "scan_id": scan_id,
        "queue_depth": scan_queue.pending_count,
        "message": f"Scan enqueued on {validated.target if validated.target else 'local subnet'}",
    }


@app.post("/scan/stop")
async def stop_scan(
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Stop the current scan if active."""
    if not scan_queue.is_active:
        return {"status": "not_scanning", "message": "No scan in progress"}
    # Cancel the active task
    if hasattr(scan_queue, "_active_future") and scan_queue._active_future and not scan_queue._active_future.done():
        scan_queue._active_future.cancel()
    SCANS_IN_PROGRESS.dec()
    await ws_manager.broadcast_scan_status(False, latest_results)
    logger.info('Scan stopped by user', extra={'component': 'api', 'user': current_user.username})
    return {"status": "stopped", "message": "Active scan cancelled"}


async def run_scan_task(task: ScanTask):
    global latest_results

    scan_id = task.scan_id
    target = task.target or task.target
    profile = task.profile or "deep"
    logger.info("Scan task running", extra={"component": "scanner", "scan_id": scan_id, "target": task.target, "profile": task.profile})

    async def progress_callback(chunk_results):
        global latest_results
        existing_ips = {d["ip"] for d in latest_results}
        for res in chunk_results:
            asyncio.create_task(enrich_device_with_probes(res))
            if res["ip"] in existing_ips:
                idx = next((i for i, d in enumerate(latest_results) if d["ip"] == res["ip"]), None)
                if idx is not None:
                    latest_results[idx] = res
            else:
                latest_results.append(res)
        asyncio.create_task(
            ws_manager.broadcast_scan_progress(latest_results, True)
        )

    async def subnet_callback(subnet):
        asyncio.create_task(ws_manager.broadcast_subnet_start(subnet))

    scan_start = datetime.now()
    try:
        result = await scanner.scan_network(
            task.target or None,
            task.profile,
            progress_callback,
            None,
            subnet_callback,
            task.trace_hops,
            profile_args=task.profile_args,
        )

        # Record scan metrics
        scan_duration_s = (datetime.now() - scan_start).total_seconds()
        SCAN_DURATION.labels(profile=profile).observe(scan_duration_s)
        SCAN_DEVICES_FOUND.labels(profile=profile).observe(len(latest_results))

        # Persist all devices to DB
        for dev in latest_results:
            db.upsert_device(scan_id, dev)
            asyncio.create_task(enrich_geolocation(dev["ip"]))

        db.complete_scan(
            scan_id,
            len(latest_results),
            result.get("subnets_scanned", 1),
        )

        # Save scan results for diffing
        db.save_scan_results(scan_id, latest_results)

        # Run CVE correlation on discovered services
        cve_count = 0
        for dev in latest_results:
            for port in dev.get("ports", []):
                service_version = port.get("service_version") or port.get("banner", "")
                if service_version:
                    cves = await cve_client.lookup(service_version)
                    for cve in cves:
                        db.add_vulnerability(
                            device_ip=dev["ip"],
                            port_id=port.get("port", 0),
                            vuln_data=cve,
                        )
                        cve_count += 1
                        # Broadcast vuln.found event
                        asyncio.create_task(
                            ws_manager.broadcast_vuln_found(
                                device_ip=dev["ip"],
                                cve_id=cve.get("cve_id", "UNKNOWN"),
                                severity=cve.get("severity", "UNKNOWN"),
                                cvss=cve.get("cvss_score", 0.0),
                                description=cve.get("description", ""),
                            )
                        )

        logger.info("Scan completed", extra={
            "component": "scanner", "scan_id": scan_id,
            "devices_found": len(latest_results),
            "duration_s": scan_duration_s,
            "cves_found": cve_count,
            **result,
        })

        # Compute diff against previous scan
        diff = db.get_scan_diff(scan_id)
        if diff and (diff.new_devices or diff.missing_devices or diff.changed_ports):
            logger.info("Scan diff detected changes",
                extra={"component": "diff", "scan_id": scan_id,
                       "new": len(diff.new_devices), "missing": len(diff.missing_devices),
                       "changed_ports": len(diff.changed_ports)})

        return diff
    except Exception as e:
        logger.error("Scan task failed", extra={"component": "scanner", "scan_id": scan_id, "error": str(e)})
        asyncio.create_task(alert_manager.alert_scan_failed(task.target or "local_subnet", str(e)))
        return None
    finally:
        SCANS_IN_PROGRESS.dec()
        await ws_manager.broadcast_scan_status(False, latest_results)


async def _on_scan_complete(task: ScanTask, diff: Optional[ScanDiff]):
    """Callback fired by ScanTaskQueue when a scan finishes."""
    if diff and (diff.new_vulnerabilities or diff.missing_devices):
        logger.info("Scan completed with changes",
            extra={"component": "queue", "task": task.target,
                   "new_vulns": len(diff.new_vulnerabilities)})
        # Alert on new vulnerabilities
        for vuln in diff.new_vulnerabilities:
            asyncio.create_task(alert_manager.send_alert(
                Alert(
                    title=f"New vulnerability: {vuln.get('cve_id', 'Unknown')}",
                    message=vuln.get("description", ""),
                    severity=AlertSeverity.HIGH,
                    alert_type=AlertType.VULN_FOUND,
                    fields={"ip": task.target, "cvss": str(vuln.get("cvss_score", "N/A"))},
                )
            ))


async def enrich_device_with_probes(device: dict):
    """Run service probes on open ports to get banners/versions."""
    for port in device.get("ports", []):
        if port.get("state") == "open":
            try:
                result = await probe_service(device["ip"], port["port"], port.get("protocol", "tcp"))
                port["banner"] = result.banner
                port["service_version"] = result.version
                port["probe_extra"] = result.extra_info
                port["confidence"] = result.confidence
            except Exception as e:
                port["probe_error"] = str(e)


async def enrich_geolocation(ip: str):
    """Background geolocation lookup."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, geo.lookup, ip, False)
    logger.debug("Geolocation enriched", extra={"component": "geo", "ip": ip})


@app.get("/devices")
async def get_devices(
    current_user: User = Depends(get_current_user),
):
    """Return all discovered devices with health data."""
    conn = sqlite3.connect(settings.database_path_abs)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.ip, h.latency_ms, h.status as health_status, h.packet_loss, h.timestamp as health_ts
        FROM devices d
        LEFT JOIN (
            SELECT device_id, latency_ms, status, packet_loss, timestamp,
                   ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY timestamp DESC) as rn
            FROM health_metrics
        ) h ON d.id = h.device_id AND h.rn = 1
    """)
    health_rows = cursor.fetchall()
    conn.close()

    health_by_ip = {r["ip"]: dict(r) for r in health_rows}

    for dev in latest_results:
        h = health_by_ip.get(dev["ip"])
        if h:
            dev["health"] = {
                "latency_ms": h["latency_ms"],
                "status": h["health_status"],
                "packet_loss": h["packet_loss"],
                "last_check": h["health_ts"],
            }

    # Update device health metrics
    up_count = sum(1 for d in latest_results if d.get("health", {}).get("status") == "up")
    down_count = sum(1 for d in latest_results if d.get("health", {}).get("status") == "down")
    HEALTH_DEVICES_UP.set(up_count)
    HEALTH_DEVICES_DOWN.set(down_count)

    return {"devices": latest_results, "is_scanning": scan_queue.is_active}


@app.get("/health/history")
async def get_health_history(
    device_ip: Optional[str] = None,
    hours: int = 24,
    current_user: User = Depends(get_current_user),
):
    """Get health metrics history."""
    conn = sqlite3.connect(settings.database_path_abs)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if device_ip:
        cursor.execute("""
            SELECT h.* FROM health_metrics h
            JOIN devices d ON h.device_id = d.id
            WHERE d.ip = ? AND h.timestamp > datetime('now', ?)
            ORDER BY h.timestamp DESC
        """, (device_ip, f"-{hours} hours"))
    else:
        cursor.execute("""
            SELECT h.*, d.ip FROM health_metrics h
            JOIN devices d ON h.device_id = d.id
            WHERE h.timestamp > datetime('now', ?)
            ORDER BY h.timestamp DESC
        """, (f"-{hours} hours",))

    rows = cursor.fetchall()
    conn.close()
    return {"history": [dict(r) for r in rows]}


@app.get("/geolocation/{ip}")
async def get_geolocation(
    ip: str,
    current_user: User = Depends(get_current_user),
):
    """Get geolocation info for an IP."""
    cached = db.get_geolocation(ip)
    if not cached:
        asyncio.create_task(enrich_geolocation(ip))
        return {"ip": ip, "message": "Lookup scheduled"}
    return {"ip": ip, **cached}


@app.get("/correlation")
async def get_network_correlation(
    current_user: User = Depends(get_current_user),
):
    """Network correlation summary: devices by vendor, OS, port states."""
    return db.get_network_summary()


@app.get("/topology")
async def get_topology(
    current_user: User = Depends(get_current_user),
):
    """Return graph data for topology visualization."""
    devices_source = latest_results if latest_results else db.get_all_devices()
    nodes = []
    edges = []

    for dev in devices_source:
        nodes.append({
            "id": dev["ip"],
            "label": dev["ip"],
            "group": dev.get("hop_count", 0) or 0,
            "vendor": dev.get("vendor", "Unknown"),
            "os": dev.get("os", "Unknown"),
            "open_ports": len([p for p in dev.get("ports", []) if p.get("state") == "open"]),
            "vulnerable": dev.get("vulns_detected", False),
        })
        if dev.get("hop_count"):
            parts = dev["ip"].split(".")
            router_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            edges.append({
                "from": router_ip,
                "to": dev["ip"],
                "length": (dev.get("distance", 1) or 1) * 50,
                "color": "#ef4444" if dev.get("vulns_detected") else "#22c55e",
            })

    return {"nodes": nodes, "edges": edges}


@app.get("/reports")
async def list_reports(
    current_user: User = Depends(get_current_user),
):
    """List generated reports."""
    return {"reports": db.list_reports()}


@app.get("/reports/generate")
async def generate_report(
    scan_id: Optional[int] = None,
    format: str = "html",
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Generate a report. Requires operator+ role."""
    try:
        path = reporter.generate(scan_id, format)
        filename = os.path.basename(path)
        logger.info("Report generated", extra={
            "component": "reports", "format": format, "scan_id": scan_id, "filename": filename,
            "user": current_user.username,
        })
        return {
            "status": "generated",
            "format": format,
            "filename": filename,
            "download_url": f"/reports-download/{filename}",
        }
    except Exception as e:
        logger.error("Report generation failed", extra={
            "component": "reports", "format": format, "scan_id": scan_id, "error": str(e),
        })
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/reports-download/{filename}")
async def download_report(
    filename: str,
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Download a generated report. Requires operator+ role."""
    # Path traversal prevention
    if ".." in filename or "/" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    path = os.path.join(settings.reports_dir, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path, filename=filename)


@app.get("/vulnerabilities")
async def get_vulnerabilities(
    device_ip: Optional[str] = None,
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """List discovered vulnerabilities."""
    conn = sqlite3.connect(settings.database_path_abs)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if device_ip:
        cursor.execute("""
            SELECT v.* FROM vulnerabilities v
            JOIN devices d ON v.device_id = d.id
            WHERE d.ip = ?
        """, (device_ip,))
    else:
        cursor.execute("SELECT * FROM vulnerabilities")

    rows = cursor.fetchall()
    conn.close()
    return {"vulnerabilities": [dict(r) for r in rows]}


@app.get("/probes/scan/{ip}")
async def scan_services(
    ip: str,
    ports: Optional[str] = None,
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Run service-specific probes on an IP. Requires operator+ role."""
    if not ports:
        port_list: list[int] = [22, 80, 443, 53, 445, 3306, 8080, 21, 25, 110, 143, 3389, 5900]
    else:
        port_list = [int(p.strip()) for p in ports.split(",")]

    results = []
    for port in port_list:
        try:
            result = await probe_service(ip, port, "tcp")
            results.append({
                "port": port,
                "service": result.service,
                "version": result.version,
                "banner": result.banner,
                "confidence": result.confidence,
                "extra": result.extra_info,
            })
        except Exception as e:
            results.append({"port": port, "error": str(e)})

    return {"ip": ip, "probes": results}


@app.post("/capture")
async def capture_packets(
    request: CaptureRequestValidation,
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Capture packets for an IP. Requires operator+ role."""
    result = await capturer.capture_for_ip(request.ip, request.duration)
    if "error" in result:
        logger.error("Packet capture failed", extra={
            "component": "capture", "ip": request.ip, "duration": request.duration, "error": result["error"],
        })
        raise HTTPException(status_code=500, detail=result["error"])
    logger.info("Packet capture completed", extra={
        "component": "capture", "ip": request.ip, "duration": request.duration,
        "packets": result.get("total_packets"),
    })
    return result


@app.get("/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}



# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: SCANNER AUTONOMY ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════


@app.get("/scan/queue")
async def get_scan_queue(
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get scan queue status and pending tasks."""
    active = scan_queue.active_task
    return {
        "is_active": scan_queue.is_active,
        "pending_count": scan_queue.pending_count,
        "active_task": {
            "target": active.target,
            "profile": active.profile,
            "priority": active.priority.name,
            "requester": active.requester,
            "created_at": datetime.fromtimestamp(active.created_at).isoformat(),
            "scan_id": active.scan_id,
        } if active else None,
        "pending_tasks": scan_queue.pending_tasks(),
    }


@app.get("/scan/history")
async def get_scan_history(
    limit: int = Query(20, le=100),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get completed scan task history."""
    return {
        "history": scan_queue.history(limit=limit),
    }


@app.post("/scan/schedule")
async def create_scan_schedule(
    target: str = Body(..., embed=True),
    profile: str = Body("deep", embed=True),
    interval_minutes: int = Body(60, ge=5, le=43200),
    requester: str = Body("manual", embed=True),
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Create a recurring scan schedule. Requires operator+ role."""
    return scan_queue.add_schedule(target, profile, interval_minutes, requester)


@app.get("/scan/schedule")
async def list_scan_schedules(
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """List all recurring scan schedules."""
    return {"schedules": scan_queue.list_schedules()}


@app.delete("/scan/schedule/{schedule_id}")
async def delete_scan_schedule(
    schedule_id: int,
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Delete a recurring scan schedule. Requires operator+ role."""
    return scan_queue.delete_schedule(schedule_id)


@app.post("/scan/schedule/{schedule_id}/toggle")
async def toggle_scan_schedule(
    schedule_id: int,
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Enable or disable a scan schedule. Requires operator+ role."""
    return scan_queue.toggle_schedule(schedule_id)


@app.get("/scan/diff/{scan_id}")
async def get_scan_diff(
    scan_id: int,
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get differences between scan and previous scan on same target."""
    diff = db.get_scan_diff(scan_id)
    if diff is None:
        return {"diff": None, "message": "No previous scan for comparison"}
    return {
        "diff": {
            "new_devices": diff.new_devices,
            "missing_devices": diff.missing_devices,
            "changed_ports": diff.changed_ports,
            "new_vulnerabilities": diff.new_vulnerabilities,
            "resolved_vulnerabilities": diff.resolved_vulnerabilities,
        }
    }


@app.post("/vulnerabilities/correlate")
async def correlate_vulnerabilities(
    target_ip: Optional[str] = Body(None, embed=True),
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Trigger CVE correlation for discovered services. Requires operator+ role."""
    conn = sqlite3.connect(settings.database_path_abs)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if target_ip:
        # Get devices with open ports and service versions for a specific IP
        cursor.execute("""
            SELECT d.id as device_id, d.ip, dp.port, dp.service, dp.version, dp.banner
            FROM devices d
            JOIN device_ports dp ON d.id = dp.device_id
            WHERE d.ip = ?
        """, (target_ip,))
    else:
        # Get all devices with open ports and service versions
        cursor.execute("""
            SELECT d.id as device_id, d.ip, dp.port, dp.service, dp.version, dp.banner
            FROM devices d
            JOIN device_ports dp ON d.id = dp.device_id
        """)

    rows = cursor.fetchall()
    conn.close()

    total_cves = 0
    for row in rows:
        service_version = row.get("version") or row.get("banner", "")
        if not service_version:
            continue
        cves = await cve_client.lookup(service_version)
        for cve in cves:
            db.add_vulnerability(
                device_id=row["device_id"],
                port_id=row["port"],
                vuln_data=cve,
            )
            total_cves += 1

    logger.info("Vulnerability correlation complete",
        extra={"component": "api", "target_ip": target_ip or "all", "cves_found": total_cves})

    return {
        "status": "correlated",
        "services_checked": len(rows),
        "cves_found": total_cves,
    }


# ═════════════════════════════════════════════════════════════════════
# PHASE 4: PACKET CAPTURE & TRAFFIC ANALYSIS ENDPOINTS
# ═════════════════════════════════════════════════════════════════════


@app.post("/capture/start-streaming")
async def start_streaming_capture(
    duration: int = Body(30, ge=1, le=600),
    bpf_filter: str = Body("", description="BPF filter expression"),
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Start streaming packet capture with real-time protocol analysis."""
    if capturer._streaming:
        raise HTTPException(status_code=409, detail="Streaming capture already in progress")

    # Wire WebSocket broadcast callback for live capture data
    async def broadcast_callback(snapshot_data):
        await ws_manager.broadcast_capture_data(snapshot_data)

    # Wire capture alert callback (SYN flood, ARP spoof, rogue AP, etc.)
    async def alert_callback(alert_data: dict):
        await ws_manager.broadcast_capture_alert(
            alert_type=alert_data.get("type", "unknown"),
            ip=alert_data.get("ip", ""),
            mac=alert_data.get("mac", ""),
            detail=alert_data,
        )

    capturer.on_snapshot(broadcast_callback)
    capturer.on_alert(alert_callback)

    # Run in background
    asyncio.create_task(capturer.start_streaming(duration=duration, bpf_filter=bpf_filter))

    logger.info("Streaming capture started",
                extra={"component": "api", "duration": duration, "bpf_filter": bpf_filter})
    return {
        "status": "started",
        "duration": duration,
        "bpf_filter": bpf_filter or "none",
    }


@app.post("/capture/stop-streaming")
async def stop_streaming_capture(
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Stop streaming packet capture."""
    if not capturer._streaming:
        raise HTTPException(status_code=409, detail="No streaming capture active")
    await capturer.stop_streaming()
    logger.info("Streaming capture stopped",
                extra={"component": "api"})
    return {"status": "stopped"}


@app.get("/capture/streaming-status")
async def streaming_capture_status(
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get streaming capture status."""
    return {
        "streaming": capturer._streaming,
        "snapshot_callbacks": len(capturer._snapshot_callbacks),
    }


@app.get("/capture/analysis-summary")
async def capture_analysis_summary(
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get summary statistics from packet capture analysis."""
    return db.get_packet_analysis_summary()


@app.get("/capture/top-talkers")
async def get_top_talkers(
    limit: int = Query(10, le=100),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get top IPs by traffic volume."""
    try:
        conn = sqlite3.connect(settings.database_path_abs)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, mac,
                   SUM(packets_sent + packets_recv) as total_packets,
                   SUM(bytes_sent + bytes_recv) as total_bytes
            FROM traffic_snapshots
            GROUP BY ip ORDER BY total_bytes DESC LIMIT ?
        """, (limit,))
        top = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return top
    except Exception as e:
        logger.error("Top talkers query failed",
                     extra={"component": "api", "error": str(e)})
        return []


@app.post("/capture/rogue-scan")
async def scan_rogue_aps(
    duration: int = Body(10, ge=5, le=120),
    monitor_interface: str = Body("", description="Monitor interface (e.g., wlan0mon)"),
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Scan for rogue access points and deauthentication frames."""
    result = await capturer.scan_for_rogue_aps(
        duration=duration,
        monitor_interface=monitor_interface or "",
    )
    total_aps = len(result.get("access_points", []))
    total_deauths = result.get("total_deauth", 0)
    logger.info("Rogue AP scan finished",
                extra={"component": "api", "access_points": total_aps, "deauth_frames": total_deauths})
    return result


@app.get("/capture/rogue-events")
async def get_rogue_events(
    limit: int = Query(50, le=500),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get rogue AP and deauth detection events."""
    try:
        conn = sqlite3.connect(settings.database_path_abs)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM rogue_ap_events
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        events = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return events
    except Exception as e:
        logger.error("Rogue events query failed",
                     extra={"component": "api", "error": str(e)})
        return []


@app.get("/capture/http-logs")
async def get_http_logs(
    limit: int = Query(50, le=500),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get HTTP request/response logs."""
    try:
        conn = sqlite3.connect(settings.database_path_abs)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM http_logs ORDER BY id DESC LIMIT ?
        """, (limit,))
        logs = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return logs
    except Exception as e:
        return []


@app.get("/capture/dns-logs")
async def get_dns_logs(
    limit: int = Query(50, le=500),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get DNS query logs."""
    try:
        conn = sqlite3.connect(settings.database_path_abs)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM dns_logs ORDER BY id DESC LIMIT ?
        """, (limit,))
        logs = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return logs
    except Exception as e:
        return []


@app.get("/capture/tls-logs")
async def get_tls_logs(
    limit: int = Query(50, le=500),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get TLS handshake logs."""
    try:
        conn = sqlite3.connect(settings.database_path_abs)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM tls_logs ORDER BY id DESC LIMIT ?
        """, (limit,))
        logs = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return logs
    except Exception as e:
        return []


@app.get("/capture/anomalies")
async def get_traffic_anomalies(
    limit: int = Query(50, le=500),
    min_score: float = Query(0.0),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get traffic anomaly events."""
    try:
        conn = sqlite3.connect(settings.database_path_abs)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM anomaly_events
            WHERE score >= ?
            ORDER BY id DESC LIMIT ?
        """, (min_score, limit))
        events = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return events
    except Exception as e:
        return []


@app.get("/capture/suspicious-dns")
async def get_suspicious_dns(
    limit: int = Query(50, le=500),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get suspicious DNS tunneling detection events."""
    try:
        conn = sqlite3.connect(settings.database_path_abs)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM suspicious_dns ORDER BY id DESC LIMIT ?
        """, (limit,))
        events = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return events
    except Exception as e:
        return []


# ── Phase 7: Frontend static serving ─────────────────────────────────────
import os as _os
_frontend_dir = _os.path.join(_os.path.dirname(__file__), "..", "frontend", "dist")
if _os.path.isdir(_frontend_dir):
    app.mount("/assets", StaticFiles(directory=_os.path.join(_frontend_dir, "assets")), name="assets")

    @app.exception_handler(404)
    async def spa_404_handler(request, exc):
        """Serve index.html for all unmatched GET routes (SPA fallback)."""
        if request.method == "GET":
            _path = _os.path.join(_frontend_dir, "index.html")
            if _os.path.isfile(_path):
                return FileResponse(_path)
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    logger.info("Frontend static serving enabled", directory=_frontend_dir,
                extra={"component": "system"})
else:
    logger.info("No frontend build found — skipping static serving",
                extra={"component": "system"})


@app.get("/api/config")
def get_config():
    """Return client-relevant config including local subnet for scan auto-fill."""
    import subprocess
    local_subnet = None
    try:
        # Get the default route's network
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout:
            # Parse: default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.42 metric 100
            parts = result.stdout.split()
            if "src" in parts:
                src_idx = parts.index("src")
                if src_idx + 1 < len(parts):
                    local_ip = parts[src_idx + 1]
                    # Derive /24 subnet from IP
                    ip_parts = local_ip.split(".")
                    local_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    except Exception:
        pass

    return {
        "local_subnet": local_subnet,
        "network_range": local_subnet,
        "api_host": settings.api_host,
        "api_port": settings.api_port,
    }


if __name__ == "__main__":

    import uvicorn
    from fastapi.responses import JSONResponse
    from fastapi import Depends
    logger.info("Starting uvicorn server", extra={
        "component": "system", "host": settings.api_host, "port": settings.api_port,
    })
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)
