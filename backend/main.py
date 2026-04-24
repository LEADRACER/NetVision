from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import asyncio
import json
import os
from scanner import NetworkScanner
from capturer import PacketCapturer
from pydantic import BaseModel

# Configuration from environment
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "wlan0")

app = FastAPI(title="NetVision v2 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure captures directory exists before mounting
os.makedirs("captures", exist_ok=True)
# Mount captures directory for file downloads
app.mount("/captures", StaticFiles(directory="captures"), name="captures")

scanner = NetworkScanner()
capturer = PacketCapturer(interface=CAPTURE_INTERFACE)
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
        # Snapshot connections to avoid mutation issues
        connections = self.active_connections[:]
        async def safe_send(conn):
            try:
                await conn.send_json(message)
                return True
            except Exception:
                return False
        results = await asyncio.gather(*(safe_send(conn) for conn in connections))
        # Prune dead connections
        for conn, ok in zip(connections, results):
            if not ok:
                try:
                    self.disconnect(conn)
                except ValueError:
                    pass  # Already removed

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial data
        await websocket.send_json({"type": "update", "devices": latest_results, "is_scanning": is_scanning})
        while True:
            await websocket.receive_text() # Keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/scan")
async def start_scan(background_tasks: BackgroundTasks, target: str = None, profile: str = "deep", duration: int = None, trace_hops: bool = False):
    global is_scanning
    if is_scanning:
        return {"status": "scanning", "message": "Scan already in progress"}
    
    is_scanning = True
    await manager.broadcast({"type": "status", "is_scanning": True})
    background_tasks.add_task(run_scan_task, target, profile, duration, trace_hops)
    return {"status": "started", "message": f"Scan started on {target if target else 'local subnet'}"}

async def run_scan_task(target: str, profile: str, duration: int = None, trace_hops: bool = False):
    global latest_results, is_scanning
    
    async def progress_callback(chunk_results):
        global latest_results
        existing_ips = {d['ip'] for d in latest_results}
        for res in chunk_results:
            if res['ip'] in existing_ips:
                latest_results = [res if d['ip'] == res['ip'] else d for d in latest_results]
            else:
                latest_results.append(res)
        asyncio.create_task(manager.broadcast({"type": "update", "devices": latest_results, "is_scanning": True}))
    
    async def subnet_callback(subnet):
        asyncio.create_task(manager.broadcast({"type": "subnet_start", "subnet": subnet}))

    try:
        await scanner.scan_network(target, profile, progress_callback, duration, subnet_callback, trace_hops)
    finally:
        is_scanning = False
        await manager.broadcast({"type": "status", "is_scanning": False, "devices": latest_results})

@app.get("/devices")
async def get_devices():
    return {"devices": latest_results, "is_scanning": is_scanning}

@app.post("/capture")
async def capture_packets(request: CaptureRequest):
    # This is a blocking-style async call (it waits for the duration)
    # But because it's an 'await' on a subprocess, it won't block the event loop
    result = await capturer.capture_for_ip(request.ip, request.duration)
    return result

@app.get("/health")
def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)
