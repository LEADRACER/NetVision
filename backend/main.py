from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
from scanner import NetworkScanner

app = FastAPI(title="NetVision v2 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = NetworkScanner()
latest_results = []
is_scanning = False
active_connections: list[WebSocket] = []

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

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
async def start_scan(background_tasks: BackgroundTasks, target: str = None, profile: str = "deep"):
    global is_scanning
    if is_scanning:
        return {"status": "scanning", "message": "Scan already in progress"}
    
    is_scanning = True
    await manager.broadcast({"type": "status", "is_scanning": True})
    background_tasks.add_task(run_scan_task, target, profile)
    return {"status": "started", "message": f"Scan started on {target if target else 'local subnet'}"}

async def run_scan_task(target: str, profile: str):
    global latest_results, is_scanning
    
    # Callback to stream results chunk-by-chunk
    async def progress_callback(chunk_results):
        global latest_results
        # Update/Append results
        existing_ips = {d['ip'] for d in latest_results}
        for res in chunk_results:
            if res['ip'] in existing_ips:
                # Update existing
                latest_results = [res if d['ip'] == res['ip'] else d for d in latest_results]
            else:
                latest_results.append(res)
        
        await manager.broadcast({"type": "update", "devices": latest_results, "is_scanning": True})

    try:
        await scanner.scan_network(target, profile, progress_callback)
    finally:
        is_scanning = False
        await manager.broadcast({"type": "status", "is_scanning": False, "devices": latest_results})

@app.get("/devices")
async def get_devices():
    return {"devices": latest_results, "is_scanning": is_scanning}

@app.get("/health")
def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
