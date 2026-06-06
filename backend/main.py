from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import asyncio
import json
import os
import socket
import sqlite3
from datetime import datetime
from typing import Optional

# Import project modules
from scanner import NetworkScanner
from capturer import PacketCapturer
from database import Database
from health import NetworkHealthMonitor
from geolocation import GeoLocator
from reports import ReportGenerator
from probes import probe_service, PROBES

from pydantic import BaseModel

# Configuration from environment
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "wlan0")
DATABASE_PATH = os.getenv("DATABASE_PATH", "netvision.db")

app = FastAPI(title="NetVision v4.3 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure directories
os.makedirs("captures", exist_ok=True)
os.makedirs("reports", exist_ok=True)

# Mount static file servers
app.mount("/captures", StaticFiles(directory="captures"), name="captures")

# Initialize services
scanner = NetworkScanner()
capturer = PacketCapturer(interface=CAPTURE_INTERFACE)
db = Database(DATABASE_PATH)
geo = GeoLocator(db)
reporter = ReportGenerator(db)
health_monitor = NetworkHealthMonitor(db, interval=30)

latest_results = []
is_scanning = False

class CaptureRequest(BaseModel):
    ip: str
    duration: int = 10

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
    await health_monitor.start()
    print("[*] NetVision started — health monitoring active")

@app.on_event("shutdown")
async def shutdown_event():
    await health_monitor.stop()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        await websocket.send_json({"type": "update", "devices": latest_results, "is_scanning": is_scanning})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/scan")
async def start_scan(
    background_tasks: BackgroundTasks,
    target: Optional[str] = None,
    profile: str = "deep",
    duration: Optional[int] = None,
    trace_hops: bool = False
):
    global is_scanning
    if is_scanning:
        return {"status": "scanning", "message": "Scan already in progress"}
    
    is_scanning = True
    await manager.broadcast({"type": "status", "is_scanning": True})
    background_tasks.add_task(run_scan_task, target, profile, duration, trace_hops)
    return {"status": "started", "message": f"Scan started on {target if target else 'local subnet'}"}

@app.get("/scan/stop")
async def stop_scan():
    global is_scanning
    if not is_scanning:
        return {"status": "not_scanning", "message": "No scan in progress"}
    is_scanning = False
    await manager.broadcast({"type": "status", "is_scanning": False, "devices": latest_results})
    return {"status": "stopped", "message": "Scan stopped"}

async def run_scan_task(target: str, profile: str, duration: Optional[int], trace_hops: bool):
    global latest_results, is_scanning
    
    scan_id = db.start_scan(target, profile, duration, trace_hops)
    
    async def progress_callback(chunk_results):
        global latest_results
        existing_ips = {d['ip'] for d in latest_results}
        for res in chunk_results:
            # Enrich with service probes (async, fire-and-forget)
            asyncio.create_task(enrich_device_with_probes(res))
            
            if res['ip'] in existing_ips:
                idx = next((i for i, d in enumerate(latest_results) if d['ip'] == res['ip']), None)
                if idx is not None:
                    latest_results[idx] = res
            else:
                latest_results.append(res)
        
        asyncio.create_task(manager.broadcast({"type": "update", "devices": latest_results, "is_scanning": True}))

    async def subnet_callback(subnet):
        asyncio.create_task(manager.broadcast({"type": "subnet_start", "subnet": subnet}))

    try:
        await scanner.scan_network(target, profile, progress_callback, None, subnet_callback, trace_hops)
        # Persist all devices to DB
        for dev in latest_results:
            db.upsert_device(scan_id, dev)
            # Background geo lookup
            asyncio.create_task(enrich_geolocation(dev['ip']))
        
        db.complete_scan(scan_id, len(latest_results), scanner.last_subnets_count if hasattr(scanner, 'last_subnets_count') else 1)
    finally:
        is_scanning = False
        await manager.broadcast({"type": "status", "is_scanning": False, "devices": latest_results})

async def enrich_device_with_probes(device: dict):
    """Run service probes on open ports to get banners/versions."""
    for port in device.get('ports', []):
        if port.get('state') == 'open':
            try:
                result = await probe_service(device['ip'], port['port'], port.get('protocol', 'tcp'))
                port['banner'] = result.banner
                port['service_version'] = result.version
                port['probe_extra'] = result.extra_info
                port['confidence'] = result.confidence
            except Exception as e:
                port['probe_error'] = str(e)

async def enrich_geolocation(ip: str):
    """Background geolocation lookup."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, geo.lookup, ip, False)

@app.get("/devices")
async def get_devices():
    """Return all discovered devices with health data."""
    # Get latest health snapshot
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT d.ip, h.latency_ms, h.status as health_status, h.packet_loss, h.timestamp as health_ts
        FROM devices d
        LEFT JOIN (
            SELECT device_id, latency_ms, status, packet_loss, timestamp,
                   ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY timestamp DESC) as rn
            FROM health_metrics
        ) h ON d.id = h.device_id AND h.rn = 1
    ''')
    health_rows = cursor.fetchall()
    conn.close()
    
    health_by_ip = {r['ip']: dict(r) for r in health_rows}
    
    for dev in latest_results:
        h = health_by_ip.get(dev['ip'])
        if h:
            dev['health'] = {
                'latency_ms': h['latency_ms'],
                'status': h['health_status'],
                'packet_loss': h['packet_loss'],
                'last_check': h['health_ts']
            }
    
    return {"devices": latest_results, "is_scanning": is_scanning}

@app.get("/health/history")
async def get_health_history(device_ip: Optional[str] = None, hours: int = 24):
    """Get health metrics history."""
    import sqlite3
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    if device_ip:
        cursor.execute('''
            SELECT h.* FROM health_metrics h
            JOIN devices d ON h.device_id = d.id
            WHERE d.ip = ? AND h.timestamp > datetime('now', ?)
            ORDER BY h.timestamp DESC
        ''', (device_ip, f'-{hours} hours'))
    else:
        cursor.execute('''
            SELECT h.*, d.ip FROM health_metrics h
            JOIN devices d ON h.device_id = d.id
            WHERE h.timestamp > datetime('now', ?)
            ORDER BY h.timestamp DESC
        ''', (f'-{hours} hours',))
    
    rows = cursor.fetchall()
    conn.close()
    return {"history": [dict(r) for r in rows]}

@app.get("/geolocation/{ip}")
async def get_geolocation(ip: str):
    """Get geolocation info for an IP."""
    cached = db.get_geolocation(ip)
    if not cached:
        # Async lookup
        asyncio.create_task(enrich_geolocation(ip))
        return {"ip": ip, "message": "Lookup scheduled"}
    return {"ip": ip, **cached}

@app.get("/correlation")
async def get_network_correlation():
    """Network correlation summary: devices by vendor, OS, port states."""
    return db.get_network_summary()

@app.get("/topology")
async def get_topology():
    """Return graph data for topology visualization."""
    devices = latest_results if latest_results else db.get_all_devices()
    nodes = []
    edges = []
    
    for dev in devices:
        nodes.append({
            "id": dev['ip'],
            "label": dev['ip'],
            "group": dev.get('hop_count', 0) or 0,
            "vendor": dev.get('vendor', 'Unknown'),
            "os": dev.get('os', 'Unknown'),
            "open_ports": len([p for p in dev.get('ports', []) if p.get('state') == 'open']),
            "vulnerable": dev.get('vulns_detected', False)
        })
        if dev.get('hop_count'):
            parts = dev['ip'].split('.')
            router_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            edges.append({
                "from": router_ip,
                "to": dev['ip'],
                "length": (dev.get('distance', 1) or 1) * 50,
                "color": "#ef4444" if dev.get('vulns_detected') else "#22c55e"
            })
    
    return {"nodes": nodes, "edges": edges}

@app.get("/reports")
async def list_reports():
    return {"reports": db.list_reports()}

@app.get("/reports/generate")
async def generate_report(
    scan_id: Optional[int] = None,
    format: str = "html"
):
    try:
        path = reporter.generate(scan_id, format)
        filename = os.path.basename(path)
        return {
            "status": "generated",
            "format": format,
            "filename": filename,
            "download_url": f"/reports-download/{filename}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports-download/{filename}")
async def download_report(filename: str):
    path = os.path.join("reports", filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path, filename=filename)

@app.get("/vulnerabilities")
async def get_vulnerabilities(device_ip: Optional[str] = None):
    """List discovered vulnerabilities."""
    import sqlite3
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    if device_ip:
        cursor.execute('''
            SELECT v.* FROM vulnerabilities v
            JOIN devices d ON v.device_id = d.id
            WHERE d.ip = ?
        ''', (device_ip,))
    else:
        cursor.execute('SELECT * FROM vulnerabilities')
    
    rows = cursor.fetchall()
    conn.close()
    return {"vulnerabilities": [dict(r) for r in rows]}

@app.get("/probes/scan/{ip}")
async def scan_services(ip: str, ports: str = None):
    """Run service-specific probes on an IP."""
    if not ports:
        # Common ports to probe
        ports = [22, 80, 443, 53, 445, 3306, 8080, 21, 25, 110, 143, 3389, 5900]
    else:
        ports = [int(p.strip()) for p in ports.split(',')]
    
    results = []
    for port in ports:
        try:
            result = await probe_service(ip, port, 'tcp')
            results.append({
                "port": port,
                "service": result.service,
                "version": result.version,
                "banner": result.banner,
                "confidence": result.confidence,
                "extra": result.extra_info
            })
        except Exception as e:
            results.append({"port": port, "error": str(e)})
    
    return {"ip": ip, "probes": results}

@app.post("/capture")
async def capture_packets(request: CaptureRequest):
    result = await capturer.capture_for_ip(request.ip, request.duration)
    if 'error' in result:
        raise HTTPException(status_code=500, detail=result['error'])
    return result

@app.get("/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)
