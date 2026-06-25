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
from security import (
    SecurityHeadersMiddleware,
    ScanTargetValidation, CaptureRequestValidation,
    ProbeTargetValidation, LoginRequest, TokenRefreshRequest,
)

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
capturer = PacketCapturer(interface=settings.capture_interface)
db = Database(settings.database_path_abs)
geo = GeoLocator(db, cache_ttl=settings.geo_cache_ttl)
reporter = ReportGenerator(db)
health_monitor = NetworkHealthMonitor(db, interval=settings.health_check_interval)

latest_results = []
is_scanning = False

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


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        connections = self.active_connections[:]

        async def safe_send(conn):
            try:
                await conn.send_json(message)
                return True
            except Exception:
                return False

        results = await asyncio.gather(*(safe_send(conn) for conn in connections))
        for conn, ok in zip(connections, results):
            if not ok:
                try:
                    self.disconnect(conn)
                except ValueError:
                    pass


manager = ConnectionManager()


@app.on_event("startup")
async def startup_event():
    db.init_tables()

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
        await loop.run_in_executor(None, db.prune_health_metrics, 90)
        await loop.run_in_executor(None, db.prune_audit_log, 30)
        await loop.run_in_executor(
            None, db.prune_old_captures, 7, settings.captures_dir
        )
        logger.info("Data retention sweep complete", extra={"component": "system"})
    except Exception as e:
        logger.warning("Data retention sweep failed", extra={"component": "system", "error": str(e)})

    # ── Start health monitor ────────────────────────────────────────────
    await health_monitor.start()

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
    await health_monitor.stop()
    logger.info("NetVision shutdown complete", extra={"component": "system"})


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        await websocket.send_json({"type": "update", "devices": latest_results, "is_scanning": is_scanning})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


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
        "is_scanning": is_scanning,
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


@app.get("/scan")
async def start_scan(
    background_tasks: BackgroundTasks,
    request: Request,
    target: Optional[str] = None,
    profile: str = "deep",
    duration: Optional[int] = None,
    trace_hops: bool = False,
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Start a network scan. Requires operator+ role."""
    global is_scanning

    # Rate limit scan starts per IP
    check_scan_rate_limit(request)

    # Validate target
    validated = ScanTargetValidation(
        target=target,
        profile=profile,
        duration=duration,
        trace_hops=trace_hops,
    )

    if is_scanning:
        logger.warning("Scan requested but already in progress",
                       extra={"component": "api", "target": target, "user": current_user.username})
        return {"status": "scanning", "message": "Scan already in progress"}

    is_scanning = True
    SCANS_IN_PROGRESS.inc()
    SCANS_TOTAL.labels(profile=profile).inc()
    await manager.broadcast({"type": "status", "is_scanning": True})

    background_tasks.add_task(run_scan_task, validated.target, validated.profile, validated.duration, validated.trace_hops)
    logger.info("Scan started", extra={
        "component": "api", "target": target or "local_subnet",
        "profile": profile, "duration": duration, "trace_hops": trace_hops,
        "user": current_user.username,
    })
    return {"status": "started", "message": f"Scan started on {validated.target if validated.target else 'local subnet'}"}


@app.get("/scan/stop")
async def stop_scan(
    current_user: User = Depends(require_role(Role.OPERATOR)),
):
    """Stop the current scan. Requires operator+ role."""
    global is_scanning
    if not is_scanning:
        return {"status": "not_scanning", "message": "No scan in progress"}
    is_scanning = False
    SCANS_IN_PROGRESS.dec()
    await manager.broadcast({"type": "status", "is_scanning": False, "devices": latest_results})
    logger.info("Scan stopped by user", extra={"component": "api", "user": current_user.username})
    return {"status": "stopped", "message": "Scan stopped"}


async def run_scan_task(target: Optional[str], profile: str, duration: Optional[int], trace_hops: bool):
    global latest_results, is_scanning

    scan_id = db.start_scan(target, profile, duration, trace_hops)
    logger.info("Scan task running", extra={"component": "scanner", "scan_id": scan_id, "target": target})

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
            manager.broadcast({"type": "update", "devices": latest_results, "is_scanning": True})
        )

    async def subnet_callback(subnet):
        asyncio.create_task(manager.broadcast({"type": "subnet_start", "subnet": subnet}))

    scan_start = datetime.now()
    try:
        result = await scanner.scan_network(target, profile, progress_callback, None, subnet_callback, trace_hops)

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
        logger.info("Scan completed", extra={
            "component": "scanner", "scan_id": scan_id,
            "devices_found": len(latest_results),
            "duration_s": scan_duration_s,
            **result,
        })
    except Exception as e:
        logger.error("Scan task failed", extra={"component": "scanner", "scan_id": scan_id, "error": str(e)})
        asyncio.create_task(alert_manager.alert_scan_failed(target or "local_subnet", str(e)))
    finally:
        is_scanning = False
        SCANS_IN_PROGRESS.dec()
        await manager.broadcast({"type": "status", "is_scanning": False, "devices": latest_results})


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

    return {"devices": latest_results, "is_scanning": is_scanning}


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


if __name__ == "__main__":
    import uvicorn
    from fastapi.responses import JSONResponse
    from fastapi import Depends
    logger.info("Starting uvicorn server", extra={
        "component": "system", "host": settings.api_host, "port": settings.api_port,
    })
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)
