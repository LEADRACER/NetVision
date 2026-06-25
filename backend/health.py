import asyncio
import socket
import struct
import os
import time
import statistics
from dataclasses import dataclass
from typing import Dict, List, Optional
import sqlite3
from loguru import logger

log = logger.bind(component="health")


@dataclass
class HealthMetric:
    ip: str
    timestamp: float
    latency_ms: float
    packet_loss: bool
    status: str  # 'up', 'down', 'partial'
    jitter_ms: Optional[float] = None
    hops: Optional[int] = None


class NetworkHealthMonitor:
    """Monitors network health by pinging known devices and tracking metrics."""
    
    def __init__(self, db, interval: int = 30):
        self.db = db
        self.interval = interval  # seconds between checks
        self.running = False
        self.task = None
        self._device_states: Dict[str, str] = {}  # ip → last known state
        self._consecutive_failures: Dict[str, int] = {}  # ip → consecutive failures
        self._on_state_change = None  # callback(ip, old_state, new_state)

    def on_state_change(self, callback):
        """Register callback for device state transitions.
        Called with (ip: str, old_state: str, new_state: str, device_info: dict)."""
        self._on_state_change = callback

    async def start(self):
        """Start background health monitoring."""
        self.running = True
        self.task = asyncio.create_task(self._monitor_loop())
        log.info("Health monitor started", interval=self.interval)

    async def stop(self):
        """Stop health monitoring."""
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

    async def _monitor_loop(self):
        """Periodically ping all known devices and record health."""
        while self.running:
            try:
                devices = self.db.get_all_devices()
                tasks = [self._ping_device(dev) for dev in devices]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for dev, result in zip(devices, results):
                    if isinstance(result, HealthMetric):
                        self.db.record_health(dev['id'], result.latency_ms, result.status, result.packet_loss)
                        
                        # Track state transitions for auto-rescan
                        ip = dev['ip']
                        new_state = result.status
                        old_state = self._device_states.get(ip)
                        
                        if new_state == 'down':
                            self._consecutive_failures[ip] = self._consecutive_failures.get(ip, 0) + 1
                        else:
                            self._consecutive_failures[ip] = 0
                        
                        if old_state and old_state != new_state:
                            log.info("Device state changed", ip=ip, old=old_state, new=new_state)
                            if self._on_state_change:
                                asyncio.create_task(self._on_state_change(ip, old_state, new_state, dev))
                        
                        self._device_states[ip] = new_state
                
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Health monitor error", error=str(e))
                await asyncio.sleep(self.interval)

    async def _ping_device(self, device: Dict) -> HealthMetric:
        """Ping a single device and return health metric."""
        ip = device['ip']
        pings = []
        packet_loss = False
        status = 'down'
        
        for attempt in range(3):  # 3 ping attempts
            try:
                latency = await self._single_ping(ip)
                if latency is not None:
                    pings.append(latency)
                    status = 'up'
            except Exception:
                pass
            await asyncio.sleep(0.2)
        
        if len(pings) == 0:
            status = 'down'
            packet_loss = True
            avg_latency = None
        else:
            packet_loss = len(pings) < 3
            avg_latency = statistics.mean(pings)
            jitter = statistics.stdev(pings) if len(pings) > 1 else 0
        
        return HealthMetric(
            ip=ip,
            timestamp=time.time(),
            latency_ms=avg_latency or 0,
            packet_loss=packet_loss,
            status=status,
            jitter_ms=jitter if len(pings) > 1 else None
        )

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum (RFC 1071)."""
        if len(data) % 2 != 0:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    async def _single_ping(self, ip: str, timeout: int = 2) -> Optional[float]:
        """Single ICMP ping using raw socket (requires root on Linux)."""
        try:
            # Create raw socket (requires root)
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                sock.settimeout(timeout)
                
                # Build ICMP echo request
                icmp_type = 8  # Echo request
                icmp_code = 0
                icmp_id = os.getpid() & 0xFFFF
                icmp_seq = 1
                
                # Build header with zero checksum first
                header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_id, icmp_seq)
                # Payload (timestamp for RTT)
                payload = struct.pack('!d', time.time())
                # Calculate proper checksum over header + payload
                checksum = self._calculate_checksum(header + payload)
                # Rebuild with correct checksum
                header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
                packet = header + payload
                
                start = time.time()
                sock.sendto(packet, (ip, 1))
                reply, _ = sock.recvfrom(1024)
                elapsed = (time.time() - start) * 1000  # ms
                
                # Validate it's an echo reply (type 0)
                icmp_header = reply[20:28]  # ICMP header starts at byte 20 in IP packet
                icmp_type, = struct.unpack('!B', icmp_header[:1])
                if icmp_type == 0:  # Echo reply
                    return elapsed
        except PermissionError:
            # Fallback to TCP ping (port 80) if no raw socket
            return await self._tcp_ping(ip, 80, timeout)
        except Exception:
            pass
        return None

    async def _tcp_ping(self, ip: str, port: int, timeout: int) -> Optional[float]:
        """TCP connect ping (works without raw socket)."""
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            elapsed = (time.time() - start) * 1000
            sock.close()
            if result == 0:
                return elapsed
        except Exception:
            pass
        return None

    def get_health_summary(self) -> Dict:
        """Get current health summary for all devices."""
        # Get latest health metric for each device
        conn = sqlite3.connect(self.db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT h.*, d.ip, d.vendor, d.hostname
            FROM health_metrics h
            JOIN devices d ON h.device_id = d.id
            WHERE h.timestamp = (
                SELECT MAX(timestamp) FROM health_metrics WHERE device_id = h.device_id
            )
        ''')
        rows = cursor.fetchall()
        conn.close()
        
        return {
            'devices': [dict(r) for r in rows],
            'total_monitored': len(rows),
            'up': sum(1 for r in rows if r['status'] == 'up'),
            'down': sum(1 for r in rows if r['status'] == 'down')
        }
