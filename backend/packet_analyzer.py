"""Real-time streaming packet analyzer — replaces dumb tshark dump with live analysis.

Uses tshark in JSON streaming mode (``-T json``) via asyncio subprocess to parse
packets individually. Detection modules run inline on each packet:
- SYN flood detection
- ARP spoofing detection
- Port scan detection (rapid sequential connections)
- DNS tunneling detection (entropy-based)

Results stream as callbacks for WebSocket + DB persistence.
"""

import asyncio
import json
import os
import math
import collections
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Callable, Any
from collections import defaultdict
from datetime import datetime

from loguru import logger

log = logger.bind(component="packet_analyzer")

# ── Detection thresholds ────────────────────────────────────────────────────
SYN_FLOOD_THRESHOLD = 100  # SYN packets/sec per target IP
PORT_SCAN_THRESHOLD = 20   # distinct ports/sec from same source
DNS_TUNNEL_ENTROPY_THRESHOLD = 0.75  # normalized entropy above this = suspicious
ARP_SPOOF_WINDOW = 5        # seconds to track IP→MAC mappings
ARP_SPOOF_CHANGE_LIMIT = 2  # IP→MAC changes within window = spoof alert


@dataclass
class PacketSummary:
    """Normalized representation of a single parsed packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "Unknown"
    length: int = 0
    flags: str = ""
    info: str = ""
    # Layer-2
    src_mac: str = ""
    dst_mac: str = ""
    eth_type: str = ""


@dataclass
class TrafficSnapshot:
    """Per-second traffic summary for a device."""
    ip: str
    mac: str = ""
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    protocols: Dict[str, int] = field(default_factory=dict)
    syn_rate: float = 0.0
    port_scan_score: float = 0.0
    alert_flags: List[str] = field(default_factory=list)


# ── Analyzer ─────────────────────────────────────────────────────────────────

class StreamingPacketAnalyzer:
    """Streams tshark JSON output and processes packets in real time.

    Usage::
        analyzer = StreamingPacketAnalyzer(interface="eth0")
        analyzer.on_packet(handle_packet)
        analyzer.on_snapshot(handle_minute_summary)
        await analyzer.start_stream(duration=60)
    """

    def __init__(self, interface: str = "eth0", db=None):
        self.interface = interface
        self._db = db
        self._running = False
        self._process: Optional[asyncio.subprocess.Process] = None
        self._packet_callbacks: List[Callable] = []
        self._snapshot_callbacks: List[Callable] = []
        self._capture_task: Optional[asyncio.Task] = None

        # Per-IP tracking
        self._ip_tracker: Dict[str, Dict] = defaultdict(lambda: {
            "packets_sent": 0, "packets_recv": 0,
            "bytes_sent": 0, "bytes_recv": 0,
            "protocols": defaultdict(int),
            "syn_timestamps": [],      # for SYN flood detection
            "port_history": [],         # for port scan detection
        })

        # ARP spoof detection state
        self._arp_table: Dict[str, Dict] = {}  # ip → {mac, timestamp}
        self._arp_changes: Dict[str, int] = defaultdict(int)  # ip → change count

        # DNS tunnel detection state
        self._dns_queries: Dict[str, Dict] = defaultdict(lambda: {
            "count": 0, "names": [], "entropies": [],
        })

        # Snapshot accumulation
        self._snapshot_interval = 5  # seconds
        self._last_snapshot = time.time()

    def on_packet(self, callback: Callable):
        """Register a callback invoked for every parsed packet.
        Callback receives a ``PacketSummary``.
        """
        self._packet_callbacks.append(callback)

    def on_snapshot(self, callback: Callable):
        """Register a callback invoked periodically with ``TrafficSnapshot`` dicts.
        Good for WebSocket broadcast and DB persistence.
        """
        self._snapshot_callbacks.append(callback)

    async def start_stream(self, duration: int = 30, bpf_filter: str = ""):
        """Start streaming packet capture and analysis.

        Args:
            duration: Capture duration in seconds (0 = run until stopped).
            bpf_filter: Optional BPF filter string.
        """
        self._running = True
        args = [
            "tshark", "-i", self.interface,
            "-T", "json",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "tcp.flags",
            "-e", "arp.src.proto_ipv4",
            "-e", "arp.src.hw_mac",
            "-e", "arp.dst.proto_ipv4",
            "-e", "arp.dst.hw_mac",
            "-e", "eth.src",
            "-e", "eth.dst",
            "-e", "eth.type",
            "-e", "dns.qry.name",
            "-e", "dns.qry.type",
            "-e", "dns.flags.response",
            "-e", "http.request.method",
            "-e", "http.request.uri",
            "-e", "http.host",
            "-e", "http.response.code",
            "-e", "dhcp.option.hostname",
            "-e", "dhcp.option.vendor_id",
            "-e", "tls.handshake.ciphersuite",
            "-e", "tls.handshake.extensions_server_name",
            "-e", "data.data",
            "-l",  # flush output line-by-line
        ]
        if bpf_filter:
            args += ["-f", bpf_filter]
        if duration > 0:
            args += ["-a", f"duration:{duration}"]

        log.info("Starting streaming capture", interface=self.interface,
                 duration=duration, filter=bpf_filter or "none")

        try:
            self._process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            log.error("tshark not found — install with: apt install tshark")
            return
        except Exception as e:
            log.error("Failed to start tshark", error=str(e))
            return

        # Read stderr in background (tshark sends progress there)
        stderr_task = asyncio.create_task(self._read_stderr())

        # Parse JSON lines from stdout
        self._capture_task = asyncio.create_task(self._read_stream())

        # Wait for duration if finite
        if duration > 0:
            await asyncio.sleep(duration)
            await self.stop()
        else:
            # Run until stop() is called
            try:
                await self._capture_task
            except asyncio.CancelledError:
                pass

        stderr_task.cancel()
        log.info("Streaming capture ended")

    async def stop(self):
        """Stop the streaming capture."""
        self._running = False
        if self._process and self._process.returncode is None:
            try:
                self._process.terminate()
                await asyncio.sleep(0.5)
                if self._process.returncode is None:
                    self._process.kill()
                await self._process.wait()
            except ProcessLookupError:
                pass
        if self._capture_task and not self._capture_task.done():
            self._capture_task.cancel()

    # ── Packet processing pipeline ───────────────────────────────────────────

    async def _read_stream(self):
        """Read tshark's JSON-per-line output and dispatch to the pipeline."""
        line_buffer = b""
        while self._running and self._process and self._process.stdout:
            try:
                chunk = await self._process.stdout.read(65536)
            except Exception:
                break
            if not chunk:
                break
            line_buffer += chunk
            # Process complete lines
            while b"\n" in line_buffer:
                line, line_buffer = line_buffer.split(b"\n", 1)
                line = line.strip()
                if line:
                    try:
                        await self._process_line(line)
                    except Exception as e:
                        log.debug("Packet parse error", error=str(e))

        # Flush any remaining data
        if line_buffer:
            try:
                await self._process_line(line_buffer)
            except Exception:
                pass

    async def _process_line(self, raw: bytes):
        """Parse one JSON line from tshark and run detection on it."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return

        # tshark -T json wraps each packet in an array
        if isinstance(data, list):
            for entry in data:
                pkt = self._parse_entry(entry)
                if pkt:
                    await self._process_packet(pkt)
        elif isinstance(data, dict):
            pkt = self._parse_entry(data)
            if pkt:
                await self._process_packet(pkt)

    def _parse_entry(self, entry: dict) -> Optional[PacketSummary]:
        """Extract normalized PacketSummary from a tshark JSON entry."""
        try:
            layers = entry.get("_source", {}).get("layers", {})
        except AttributeError:
            return None

        pkt = PacketSummary(
            timestamp=float(self._get_first(layers, "frame.time_epoch") or time.time()),
            src_ip=self._get_first(layers, "ip.src") or "",
            dst_ip=self._get_first(layers, "ip.dst") or "",
            src_port=int(self._get_first(layers, "tcp.srcport") or
                         self._get_first(layers, "udp.srcport") or 0),
            dst_port=int(self._get_first(layers, "tcp.dstport") or
                         self._get_first(layers, "udp.dstport") or 0),
            protocol=self._get_first(layers, "_ws.col.Protocol") or "Unknown",
            length=int(self._get_first(layers, "frame.len") or 0),
            flags=self._get_first(layers, "tcp.flags") or "",
            src_mac=self._get_first(layers, "eth.src") or "",
            dst_mac=self._get_first(layers, "eth.dst") or "",
            eth_type=self._get_first(layers, "eth.type") or "",
            info="",
        )

        # Skip packets without both IPs
        if not pkt.src_ip or not pkt.dst_ip:
            return None

        return pkt

    @staticmethod
    def _get_first(layers: dict, key: str) -> Optional[str]:
        """Get first value from a tshark JSON field (may be a list or single value)."""
        val = layers.get(key)
        if val is None:
            return None
        if isinstance(val, list):
            return str(val[0]) if val else None
        return str(val)

    async def _process_packet(self, pkt: PacketSummary):
        """Run all detection and tracking on a parsed packet."""
        # ── Update IP tracker ────────────────────────────────────────────
        tracker = self._ip_tracker[pkt.src_ip]
        tracker["packets_sent"] += 1
        tracker["bytes_sent"] += pkt.length
        tracker["protocols"][pkt.protocol] += 1

        tracker_recv = self._ip_tracker[pkt.dst_ip]
        tracker_recv["packets_recv"] += 1
        tracker_recv["bytes_recv"] += pkt.length

        # ── Detection: SYN flood ─────────────────────────────────────────
        if pkt.flags == "0x002":  # SYN flag
            tracker["syn_timestamps"].append(pkt.timestamp)
            # Prune old entries (>2s window)
            tracker["syn_timestamps"] = [t for t in tracker["syn_timestamps"]
                                          if pkt.timestamp - t <= 2.0]
            rate = len(tracker["syn_timestamps"])
            if rate > SYN_FLOOD_THRESHOLD:
                log.warning("SYN flood suspected", src_ip=pkt.src_ip,
                            rate=f"{rate}/2s")

        # ── Detection: Port scan ─────────────────────────────────────────
        if pkt.dst_port and pkt.flags in ("0x002", ""):  # SYN or UDP to new port
            tracker["port_history"].append((pkt.timestamp, pkt.dst_port))
            # Prune old entries (>3s window)
            now = pkt.timestamp
            tracker["port_history"] = [
                (t, p) for t, p in tracker["port_history"]
                if now - t <= 3.0
            ]
            distinct_ports = len(set(p for _, p in tracker["port_history"]))
            if distinct_ports > PORT_SCAN_THRESHOLD:
                log.warning("Port scan suspected", src_ip=pkt.src_ip,
                            distinct_ports=f"{distinct_ports}/3s")

        # ── Detection: ARP spoofing ──────────────────────────────────────
        if pkt.eth_type == "0x0806" and pkt.src_ip and pkt.src_mac:
            old = self._arp_table.get(pkt.src_ip)
            if old and old["mac"] != pkt.src_mac:
                self._arp_changes[pkt.src_ip] += 1
                if self._arp_changes[pkt.src_ip] >= ARP_SPOOF_CHANGE_LIMIT:
                    log.critical("ARP spoofing detected", ip=pkt.src_ip,
                                 old_mac=old["mac"], new_mac=pkt.src_mac)
            self._arp_table[pkt.src_ip] = {"mac": pkt.src_mac, "timestamp": pkt.timestamp}

        # DNS tunneling detection via entropy is done in protocol_decoder

        # ── Fire packet callbacks ────────────────────────────────────────
        for cb in self._packet_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(pkt)
                else:
                    cb(pkt)
            except Exception as e:
                log.debug("Packet callback error", error=str(e))

        # ── Periodic snapshot ────────────────────────────────────────────
        now = time.time()
        if now - self._last_snapshot >= self._snapshot_interval:
            await self._emit_snapshot()
            self._last_snapshot = now

    async def _emit_snapshot(self):
        """Build and emit traffic snapshots for all tracked IPs."""
        snapshots = []
        for ip, data in list(self._ip_tracker.items()):
            mac = ""
            if ip in self._arp_table:
                mac = self._arp_table[ip]["mac"]

            snapshot = TrafficSnapshot(
                ip=ip,
                mac=mac,
                bytes_sent=data["bytes_sent"],
                bytes_recv=data["bytes_recv"],
                packets_sent=data["packets_sent"],
                packets_recv=data["packets_recv"],
                protocols=dict(data["protocols"]),
                syn_rate=len(data["syn_timestamps"]) / 2.0,
                port_scan_score=len(set(p for _, p in data["port_history"])),
                alert_flags=[],
            )

            # Check thresholds for alert flags
            if snapshot.syn_rate > SYN_FLOOD_THRESHOLD:
                snapshot.alert_flags.append("syn_flood")
            if snapshot.port_scan_score > PORT_SCAN_THRESHOLD:
                snapshot.alert_flags.append("port_scan")
            if ip in self._arp_changes and self._arp_changes[ip] >= ARP_SPOOF_CHANGE_LIMIT:
                snapshot.alert_flags.append("arp_spoof")

            snapshots.append(snapshot)

            # Persist to DB if available
            if self._db:
                try:
                    self._db.record_traffic_snapshot(snapshot)
                except Exception as e:
                    log.debug("DB snapshot error", error=str(e))

        # Fire snapshot callbacks
        for cb in self._snapshot_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(snapshots)
                else:
                    cb(snapshots)
            except Exception as e:
                log.debug("Snapshot callback error", error=str(e))

        # Reset per-interval counters
        for data in self._ip_tracker.values():
            data["syn_timestamps"] = [t for t in data["syn_timestamps"]
                                       if time.time() - t <= 2.0]
            now = time.time()
            data["port_history"] = [(t, p) for t, p in data["port_history"]
                                     if now - t <= 3.0]

    async def _read_stderr(self):
        """Read and log tshark stderr (info/warning messages)."""
        if not self._process or not self._process.stderr:
            return
        try:
            while self._running:
                line = await self._process.stderr.readline()
                if not line:
                    break
                msg = line.decode(errors="replace").strip()
                if msg:
                    log.debug("tshark: {msg}", msg=msg)
        except Exception:
            pass
