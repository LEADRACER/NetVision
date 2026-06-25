"""Packet capture — streaming analysis, rogue AP / deauth detection, file capture.

Integrates ``StreamingPacketAnalyzer``, ``ProtocolDecoder``, and ``TrafficBaseliner``
into a single orchestrated capture pipeline. Supports:
- File-based capture (existing ``capture_for_ip``, backward compatible)
- Streaming analysis with real-time protocol decoding
- Rogue AP and deauthentication detection from monitor-mode captures
"""

import asyncio
import collections
import datetime
import json
import math
import os
import time
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from collections import defaultdict
from loguru import logger

log = logger.bind(component="capture")


class PacketCapturer:
    """Packet capture orchestrator — combines streaming analysis, protocol decoding,
    rogue AP detection, and file-based capture.

    Usage::
        capturer = PacketCapturer(interface="wlan0", db=database)
        capturer.on_snapshot(broadcast_to_websocket)
        await capturer.start_streaming(duration=60)
    """

    def __init__(self, interface: str = "wlan0", db=None, captures_dir: str = "captures"):
        self.interface = interface
        self._db = db
        self.captures_dir = captures_dir
        self._streaming = False

        # Components (lazy-initialized by start_streaming)
        self._analyzer = None
        self._decoder = None
        self._baseliner = None

        # Callbacks
        self._snapshot_callbacks: List[Callable] = []
        self._alert_callbacks: List[Callable] = []

        # Cleanup
        if not os.path.exists(self.captures_dir):
            os.makedirs(self.captures_dir)

        # Rogue AP tracking
        self._known_bssids: set = set()

    def on_snapshot(self, callback: Callable):
        """Register callback for traffic snapshots (called every ~5s during streaming)."""
        self._snapshot_callbacks.append(callback)

    def on_alert(self, callback: Callable):
        """Register callback for detection alerts (SYN flood, ARP spoof, rogue AP, etc.)."""
        self._alert_callbacks.append(callback)

    # ── Streaming Capture ──────────────────────────────────────────────────

    async def start_streaming(self, duration: int = 30, bpf_filter: str = ""):
        """Start streaming packet capture with real-time analysis.

        Integrates the packet analyzer, protocol decoder, traffic baseliner,
        and rogue AP detection into a single async pipeline.
        """
        if self._streaming:
            log.warning("Streaming capture already in progress")
            return

        self._streaming = True
        log.info("Starting streaming capture", interface=self.interface,
                 duration=duration)

        # Initialize components
        from packet_analyzer import StreamingPacketAnalyzer
        from protocol_decoder import ProtocolDecoder
        from traffic_baseline import TrafficBaseliner

        self._analyzer = StreamingPacketAnalyzer(interface=self.interface, db=self._db)
        self._decoder = ProtocolDecoder(db=self._db)
        self._baseliner = TrafficBaseliner(db=self._db)

        # Wire pipeline: analyzer → decoder → baseliner → callbacks
        self._analyzer.on_snapshot(self._on_analyzer_snapshot)
        self._decoder.on_decoded(self._on_decoded_event)

        # Run together
        try:
            await self._analyzer.start_stream(duration=duration, bpf_filter=bpf_filter)
        finally:
            self._streaming = False
            log.info("Streaming capture ended")

    async def stop_streaming(self):
        """Stop streaming capture."""
        if self._analyzer:
            await self._analyzer.stop()
        self._streaming = False

    async def _on_analyzer_snapshot(self, snapshots):
        """Pipeline stage: analyzer snapshot → baseliner + callbacks."""
        for snap in snapshots:
            # Update baselines
            if self._baseliner:
                self._baseliner.update(
                    ip=snap.ip,
                    mac=snap.mac,
                    bytes_sent=snap.bytes_sent,
                    bytes_recv=snap.bytes_recv,
                    packets_sent=snap.packets_sent,
                    packets_recv=snap.packets_recv,
                    protocols=snap.protocols,
                )

            # Fire alert callbacks for flagged devices
            for flag in snap.alert_flags:
                for cb in self._alert_callbacks:
                    try:
                        cb({
                            "type": flag,
                            "ip": snap.ip,
                            "mac": snap.mac,
                            "syn_rate": getattr(snap, 'syn_rate', 0),
                            "port_scan_score": getattr(snap, 'port_scan_score', 0),
                            "timestamp": time.time(),
                        })
                    except Exception as e:
                        log.debug("Alert callback error", error=str(e))

        # Fire snapshot callbacks (WebSocket broadcast)
        snapshot_dicts = [
            {
                "ip": s.ip,
                "mac": s.mac,
                "bytes_sent": s.bytes_sent,
                "bytes_recv": s.bytes_recv,
                "packets": s.packets_sent + s.packets_recv,
                "protocols": s.protocols,
                "alert_flags": s.alert_flags,
            }
            for s in snapshots
        ]
        for cb in self._snapshot_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(snapshot_dicts)
                else:
                    cb(snapshot_dicts)
            except Exception as e:
                log.debug("Snapshot callback error", error=str(e))

    def _on_decoded_event(self, event: str, data):
        """Pipeline stage: protocol decoder events → baseliner + logging."""
        # Feed peer tracking for baselines
        if event == "http_request" and self._baseliner:
            self._baseliner.add_peer(data.src_ip, data.dst_ip)

    # ── Rogue AP / Deauth Detection ────────────────────────────────────────

    async def scan_for_rogue_aps(self, duration: int = 10, monitor_interface: str = ""):
        """Capture beacon frames and deauth packets on a monitor-mode interface.

        Returns detected rogue APs and deauth events.

        Args:
            duration: Scan duration in seconds.
            monitor_interface: Monitor-mode interface (e.g., wlan0mon).
                               Defaults to interface + "mon".
        """
        mon_iface = monitor_interface or f"{self.interface}mon"
        results = {
            "access_points": [],
            "deauth_events": [],
            "total_beacons": 0,
            "total_deauth": 0,
        }

        # Use tshark to capture beacon and deauth frames
        ts = int(time.time())
        capture_cmd = [
            "tshark", "-i", mon_iface,
            "-a", f"duration:{duration}",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "wlan.bssid",
            "-e", "wlan.fc.type_subtype",
            "-e", "wlan.ssid",
            "-e", "wlan.channel",
            "-e", "radiotap.dbm_antsignal",
            "-Y", "wlan.fc.type eq 0",  # Management frames only
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *capture_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except FileNotFoundError:
            log.error("tshark not found — install with: apt install tshark")
            return results
        except Exception as e:
            log.error("Rogue AP scan failed", error=str(e))
            return results

        if stderr:
            log.warning("tshark stderr", msg=stderr.decode(errors="replace"))

        lines = stdout.decode(errors="replace").strip().split("\n")
        if not lines or lines == [""]:
            log.info("No management frames captured", interface=mon_iface)
            return results

        for line in lines:
            parts = line.split("\t")
            if len(parts) < 6:
                continue

            try:
                timestamp = float(parts[0])
            except ValueError:
                continue
            src = parts[1] or ""
            dst = parts[2] or ""
            bssid = parts[3] or ""
            subtype = parts[4] or ""
            ssid = parts[5] or ""
            channel = int(parts[6]) if len(parts) > 6 and parts[6] else 0
            rssi = int(parts[7]) if len(parts) > 7 and parts[7] else 0

            if subtype == "8":  # Beacon frame
                results["total_beacons"] += 1
                ap_info = {
                    "bssid": bssid or src,
                    "ssid": ssid,
                    "channel": channel,
                    "rssi": rssi,
                    "timestamp": timestamp,
                }

                # Check if this is a known BSSID
                ap_bssid = ap_info["bssid"]
                if ap_bssid and ap_bssid not in self._known_bssids:
                    self._known_bssids.add(ap_bssid)
                    results["access_points"].append(ap_info)

                    # Log to DB
                    if self._db:
                        self._db.record_rogue_ap(
                            event_type="beacon",
                            bssid=ap_bssid,
                            ssid=ssid,
                            channel=channel,
                            rssi=rssi,
                        )

                    # Fire alert for new AP
                    for cb in self._alert_callbacks:
                        try:
                            cb({
                                "type": "new_ap",
                                "bssid": ap_bssid,
                                "ssid": ssid,
                                "channel": channel,
                                "timestamp": timestamp,
                            })
                        except Exception as e:
                            log.debug("Alert callback error", error=str(e))

            elif subtype == "12":  # Deauthentication frame
                results["total_deauth"] += 1
                deauth = {
                    "src": src,
                    "dst": dst,
                    "bssid": bssid,
                    "timestamp": timestamp,
                }
                results["deauth_events"].append(deauth)

                # Log to DB
                if self._db:
                    self._db.record_rogue_ap(
                        event_type="deauth",
                        bssid=bssid,
                        src_mac=src,
                        detail=f"Deauth: {src} -> {dst}",
                    )

                # Fire alert
                for cb in self._alert_callbacks:
                    try:
                        cb({
                            "type": "deauth",
                            "src": src,
                            "dst": dst,
                            "bssid": bssid,
                            "timestamp": timestamp,
                        })
                    except Exception as e:
                        log.debug("Alert callback error", error=str(e))

        # Keep AP list bounded
        if len(self._known_bssids) > 1000:
            self._known_bssids = set(list(self._known_bssids)[-500:])

        log.info("Rogue AP scan complete",
                 aps=len(results["access_points"]),
                 deauths=results["total_deauth"],
                 total_beacons=results["total_beacons"])

        return results

    # ── File-based Capture (backward compat) ───────────────────────────────

    def cleanup_old_captures(self):
        """Remove oldest captures if count exceeds max_captures."""
        max_captures = int(os.getenv("MAX_CAPTURES", "100"))
        try:
            files = [
                os.path.join(self.captures_dir, f)
                for f in os.listdir(self.captures_dir)
                if f.endswith('.pcap')
            ]
            if len(files) > max_captures:
                files.sort(key=os.path.getmtime, reverse=True)
                for old in files[max_captures:]:
                    try:
                        os.remove(old)
                    except Exception:
                        pass
        except Exception:
            pass

    async def capture_for_ip(self, ip, duration=10):
        """Backward-compatible file-based packet capture.

        Captures to pcap, then returns summary. No streaming analysis.
        """
        self.cleanup_old_captures()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"capture_{ip.replace('.', '_')}_{timestamp}.pcap"
        filepath = os.path.join(self.captures_dir, filename)

        capture_cmd = [
            "tshark", "-i", self.interface,
            "-f", f"host {ip}",
            "-a", f"duration:{duration}",
            "-w", filepath
        ]

        try:
            proc = await asyncio.create_subprocess_exec(*capture_cmd)
            await proc.wait()

            # Analyze saved file
            analyze_cmd = [
                "tshark", "-r", filepath,
                "-T", "fields",
                "-e", "_ws.col.Protocol",
                "-e", "frame.len"
            ]
            proc_analyze = await asyncio.create_subprocess_exec(
                *analyze_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc_analyze.communicate()

            lines = stdout.decode().strip().split('\n')
            protocols = collections.Counter()
            total_bytes = 0
            packet_count = 0

            if lines and lines != ['']:
                for line in lines:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        proto = parts[0].strip() or "Unknown"
                        try:
                            size = int(parts[1].strip() or 0)
                        except:
                            size = 0
                        protocols[proto] += 1
                        total_bytes += size
                        packet_count += 1

            return {
                "total_packets": packet_count,
                "total_bytes": total_bytes,
                "protocols": dict(protocols),
                "ip": ip,
                "duration": duration,
                "filename": filename,
                "file_path": filepath,
            }

        except Exception as e:
            log.error("Packet capture failed", ip=ip, duration=duration, error=str(e))
            return {"error": str(e)}

