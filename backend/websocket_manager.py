"""WebSocket event manager — heartbeat, per-client queues, subscriptions, state sync.

Features
--------
• Ping/pong heartbeat (30s interval, 10s timeout) — dead clients cleaned automatically
• Per-client asyncio.Queue — slow clients drop oldest messages rather than blocking the server
• Topic-based subscriptions — clients subscribe to specific event streams
• Versioned state — every broadcast increments a global counter; reconnecting clients
  supply ``last_version`` and receive missed events from the ring buffer
• Typed event streams — ``scan.progress``, ``health.alert``, ``vuln.found``, ``capture.data``
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Callable, Dict, List, Optional, Set

from fastapi import WebSocket, WebSocketDisconnect
from loguru import logger

# ── Constants ──────────────────────────────────────────────────────────────

HEARTBEAT_INTERVAL = 30       # seconds between ping frames
HEARTBEAT_TIMEOUT = 10        # seconds to wait for pong before disconnecting
CLIENT_QUEUE_MAX = 256        # max queued messages per client (oldest dropped)
STATE_HISTORY_SIZE = 500      # ring buffer for reconnection state sync
MAX_SUBSCRIBE_TOPICS = 32     # max topics a single client can subscribe to

# ── Event types (used as topic names for subscription) ────────────────────

EVENT_SCAN_PROGRESS = "scan.progress"
EVENT_SCAN_COMPLETE = "scan.complete"
EVENT_SCAN_STATUS   = "scan.status"
EVENT_HEALTH_ALERT  = "health.alert"
EVENT_VULN_FOUND    = "vuln.found"
EVENT_CAPTURE_DATA  = "capture.data"
EVENT_CAPTURE_ALERT = "capture.alert"
EVENT_SUBNET_START  = "scan.subnet"
EVENT_DEVICE_UPDATE = "device.update"

# ── Typed event helpers ───────────────────────────────────────────────────

def event_scan_progress(devices: list, is_scanning: bool = True) -> dict:
    return {"event": EVENT_SCAN_PROGRESS, "devices": devices, "is_scanning": is_scanning}

def event_scan_complete(devices: list, scan_id: int, is_scanning: bool = False) -> dict:
    return {"event": EVENT_SCAN_COMPLETE, "devices": devices, "scan_id": scan_id, "is_scanning": is_scanning}

def event_scan_status(is_scanning: bool, devices: Optional[list] = None) -> dict:
    return {"event": EVENT_SCAN_STATUS, "is_scanning": is_scanning, "devices": devices or []}

def event_health_alert(ip: str, old_state: str, new_state: str, device_info: dict) -> dict:
    return {
        "event": EVENT_HEALTH_ALERT,
        "ip": ip,
        "old_state": old_state,
        "new_state": new_state,
        "device_info": device_info,
        "timestamp": time.time(),
    }

def event_vuln_found(device_ip: str, cve_id: str, severity: str, cvss: float, description: str) -> dict:
    return {
        "event": EVENT_VULN_FOUND,
        "device_ip": device_ip,
        "cve_id": cve_id,
        "severity": severity,
        "cvss_score": cvss,
        "description": description,
        "timestamp": time.time(),
    }

def event_capture_data(snapshots: list) -> dict:
    return {"event": EVENT_CAPTURE_DATA, "snapshots": snapshots, "timestamp": time.time()}

def event_capture_alert(alert_type: str, ip: str, mac: str, detail: dict) -> dict:
    return {
        "event": EVENT_CAPTURE_ALERT,
        "alert_type": alert_type,
        "ip": ip,
        "mac": mac,
        **detail,
        "timestamp": time.time(),
    }

def event_device_update(devices: list) -> dict:
    return {"event": EVENT_DEVICE_UPDATE, "devices": devices}

def event_subnet_start(subnet: str) -> dict:
    return {"event": EVENT_SUBNET_START, "subnet": subnet}


# ── WebSocketClient wrapper ───────────────────────────────────────────────

class WebSocketClient:
    """A connected WebSocket client with its own message queue and heartbeat."""

    def __init__(self, websocket: WebSocket, client_id: str):
        self.websocket = websocket
        self.client_id = client_id
        self.connected_at = time.time()
        self.last_activity = time.time()
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=CLIENT_QUEUE_MAX)
        self.subscribed_topics: Set[str] = set()

        # Heartbeat management
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._consumer_task: Optional[asyncio.Task] = None
        self._pong_received = True

    def subscribe(self, topic: str):
        """Subscribe client to a topic. Empty string = all topics."""
        if len(self.subscribed_topics) < MAX_SUBSCRIBE_TOPICS:
            self.subscribed_topics.add(topic)

    def unsubscribe(self, topic: str):
        self.subscribed_topics.discard(topic)

    def is_subscribed_to(self, topic: str) -> bool:
        """Check if client should receive a message for this topic."""
        if not self.subscribed_topics:
            return True  # no subscriptions = receive everything
        if "" in self.subscribed_topics:
            return True  # empty string = wildcard
        return topic in self.subscribed_topics

    def send(self, message: dict):
        """Enqueue a message for this client. Drops oldest if queue is full."""
        self._enqueue(message)

    def _enqueue(self, message: dict):
        """Synchronous enqueue — drops oldest if queue is full."""
        try:
            self.queue.put_nowait(message)
        except asyncio.QueueFull:
            # Drop oldest to keep the client from blocking the server
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(message)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass

    # ── Internal tasks ───────────────────────────────────────────────────

    async def _heartbeat_loop(self):
        """Send ping frames every HEARTBEAT_INTERVAL, disconnect if no pong."""
        try:
            while True:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                if not self._pong_received:
                    logger.info("WebSocket heartbeat timeout", client_id=self.client_id)
                    await self.disconnect()
                    return
                self._pong_received = False
                try:
                    await self.websocket.send_json({"type": "ping"})
                except Exception:
                    await self.disconnect()
                    return
        except asyncio.CancelledError:
            pass

    async def _consumer_loop(self):
        """Pull messages from the per-client queue and send them over the wire."""
        try:
            while True:
                message = await self.queue.get()
                try:
                    await self.websocket.send_json(message)
                    self.last_activity = time.time()
                except Exception:
                    # Connection broken — put message back for others? No,
                    # this client is dead. The heartbeat or next send will
                    # trigger cleanup.
                    break
        except asyncio.CancelledError:
            pass

    async def disconnect(self):
        """Clean up this client — cancel tasks, close socket."""
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
        if self._consumer_task and not self._consumer_task.done():
            self._consumer_task.cancel()
        try:
            await self.websocket.close()
        except Exception:
            pass

    async def handle_incoming(self):
        """Process incoming messages from this client (subscriptions, pong, version)."""
        try:
            while True:
                data = await self.websocket.receive_json()
                self.last_activity = time.time()
                msg_type = data.get("type", "")
                if msg_type == "pong":
                    self._pong_received = True
                elif msg_type == "subscribe":
                    topics = data.get("topics", [])
                    for t in topics:
                        self.subscribe(t)
                    self.send({
                        "type": "subscribed",
                        "topics": list(self.subscribed_topics),
                    })
                elif msg_type == "unsubscribe":
                    topics = data.get("topics", [])
                    for t in topics:
                        self.unsubscribe(t)
                    self.send({
                        "type": "unsubscribed",
                        "topics": list(self.subscribed_topics),
                    })
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            await self.disconnect()


# ── WebSocketManager ──────────────────────────────────────────────────────

class WebSocketManager:
    """Manages all WebSocket connections with per-client queues and event streams.

    Usage
    -----
        manager = WebSocketManager()

        # In FastAPI endpoint:
        @app.websocket("/ws")
        async def ws(websocket: WebSocket):
            client = await manager.connect(websocket)
            # Optionally subscribe client:
            client.subscribe("scan.progress")
            await manager.handle_client(client)

        # Broadcast to all or by topic:
        await manager.broadcast(event_scan_progress(devices, True))
        await manager.broadcast_topic(EVENT_SCAN_PROGRESS, event_data)
    """

    def __init__(self):
        self._clients: Dict[str, WebSocketClient] = {}

        # Global state version for reconnection sync
        self._version_counter = 0
        self._state_history: List[dict] = []  # ring buffer for replay

    @property
    def active_count(self) -> int:
        """Number of currently connected clients."""
        return len(self._clients)

    async def connect(self, websocket: WebSocket) -> WebSocketClient:
        """Accept a new WebSocket connection, wrap it, start background tasks."""
        await websocket.accept()
        client_id = str(uuid.uuid4())[:8]
        client = WebSocketClient(websocket, client_id)

        # Start heartbeat and consumer background tasks
        client._heartbeat_task = asyncio.create_task(client._heartbeat_loop())
        client._consumer_task = asyncio.create_task(client._consumer_loop())

        self._clients[client_id] = client
        logger.info("WebSocket client connected", client_id=client_id, total=len(self._clients))
        return client

    async def disconnect(self, client_id: str):
        """Disconnect a specific client."""
        client = self._clients.pop(client_id, None)
        if client:
            await client.disconnect()
            logger.info("WebSocket client disconnected", client_id=client_id, total=len(self._clients))

    async def handle_client(self, client: WebSocketClient):
        """Run the incoming-message handler for a client (blocking until disconnect).

        Call this after manager.connect() — it listens for pong, subscribe,
        unsubscribe, and version sync messages.
        """
        try:
            await client.handle_incoming()
        finally:
            await self.disconnect(client.client_id)

    async def broadcast(self, message: dict, topic: str = ""):
        """Broadcast a message to ALL connected clients irrespective of topic.

        Args:
            message: The JSON-serialisable dict to send.
            topic: Optional topic string for state history tagging.
        """
        # Increment global state version
        self._version_counter += 1
        versioned = {**message, "_v": self._version_counter}

        # Store in ring buffer for reconnection sync
        if topic:
            self._state_history.append({"topic": topic, "message": versioned})
            if len(self._state_history) > STATE_HISTORY_SIZE:
                self._state_history.pop(0)

        # Send to all clients
        for client in list(self._clients.values()):
            client.send(versioned)

    async def broadcast_topic(self, topic: str, message: dict):
        """Broadcast only to clients subscribed to the given topic.

        Args:
            topic: The event topic (e.g., ``EVENT_SCAN_PROGRESS``).
            message: The JSON-serialisable dict to send.
        """
        self._version_counter += 1
        versioned = {**message, "_v": self._version_counter, "_topic": topic}

        # Store in ring buffer
        self._state_history.append({"topic": topic, "message": versioned})
        if len(self._state_history) > STATE_HISTORY_SIZE:
            self._state_history.pop(0)

        for client in list(self._clients.values()):
            if client.is_subscribed_to(topic):
                client.send(versioned)

    async def sync_client(self, client: WebSocketClient, last_version: int = 0):
        """Replay missed events to a reconnecting client.

        Args:
            client: The client to sync.
            last_version: The last ``_v`` value the client has seen (sent in
                          the initial ``{"type": "reconnect", "last_version": N}``
                          message).
        """
        if last_version <= 0:
            return
        missed = [
            entry["message"]
            for entry in self._state_history
            if entry["message"].get("_v", 0) > last_version
        ]
        for msg in missed:
            client.send(msg)

    async def broadcast_scan_progress(self, devices: list, is_scanning: bool = True):
        """Broadcast scan progress update."""
        await self.broadcast_topic(EVENT_SCAN_PROGRESS, event_scan_progress(devices, is_scanning))

    async def broadcast_scan_complete(self, devices: list, scan_id: int):
        """Broadcast scan completion."""
        await self.broadcast_topic(EVENT_SCAN_COMPLETE, event_scan_complete(devices, scan_id))

    async def broadcast_scan_status(self, is_scanning: bool, devices: Optional[list] = None):
        """Broadcast scan status change."""
        await self.broadcast_topic(EVENT_SCAN_STATUS, event_scan_status(is_scanning, devices))

    async def broadcast_health_alert(self, ip: str, old_state: str, new_state: str, device_info: dict):
        """Broadcast a health alert event."""
        await self.broadcast_topic(EVENT_HEALTH_ALERT, event_health_alert(ip, old_state, new_state, device_info))

    async def broadcast_vuln_found(self, device_ip: str, cve_id: str, severity: str, cvss: float, description: str):
        """Broadcast a vulnerability found event."""
        await self.broadcast_topic(
            EVENT_VULN_FOUND,
            event_vuln_found(device_ip, cve_id, severity, cvss, description),
        )

    async def broadcast_capture_data(self, snapshots: list):
        """Broadcast live packet capture data."""
        await self.broadcast_topic(EVENT_CAPTURE_DATA, event_capture_data(snapshots))

    async def broadcast_capture_alert(self, alert_type: str, ip: str, mac: str, detail: dict):
        """Broadcast capture detection alert."""
        await self.broadcast_topic(EVENT_CAPTURE_ALERT, event_capture_alert(alert_type, ip, mac, detail))

    async def broadcast_device_update(self, devices: list):
        """Broadcast device list update (legacy catch-all)."""
        await self.broadcast_topic(EVENT_DEVICE_UPDATE, event_device_update(devices))

    async def broadcast_subnet_start(self, subnet: str):
        """Broadcast subnet scan start."""
        await self.broadcast_topic(EVENT_SUBNET_START, event_subnet_start(subnet))

    async def shutdown(self):
        """Disconnect all clients gracefully on server shutdown."""
        for client_id in list(self._clients.keys()):
            await self.disconnect(client_id)
        logger.info("All WebSocket clients disconnected on shutdown")


# ── Module-level convenience instance ─────────────────────────────────────

manager = WebSocketManager()
