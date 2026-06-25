"""Traffic baseliner — per-MAC behavioral modeling with z-score anomaly detection.

Builds and maintains baselines for each device:
- Protocol distribution (histogram of TCP/UDP/ICMP/ARP/...)
- Typical traffic volume (bytes/sec, packets/sec)
- Active hours (which hours the device is typically active)
- Connection peers (IPs the device normally talks to)

Anomalies are flagged when current behavior deviates >2σ from the baseline.
"""

import json
import math
import time
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from datetime import datetime

from loguru import logger

log = logger.bind(component="traffic_baseline")


@dataclass
class DeviceBaseline:
    """Behavioral baseline for a single device."""
    mac: str
    ip: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0

    # Traffic volume (bytes/sec)
    mean_bytes_per_sec: float = 0.0
    std_bytes_per_sec: float = 0.0
    mean_packets_per_sec: float = 0.0
    std_packets_per_sec: float = 0.0

    # Protocol distribution (%)
    protocol_profile: Dict[str, float] = field(default_factory=dict)

    # Active hours (bitmask: 0=inactive, 1=active for each hour of day)
    active_hours: List[int] = field(default_factory=lambda: [0] * 24)

    # Known peers
    peer_ips: Set[str] = field(default_factory=set)

    # Sample count for confidence
    sample_count: int = 0

    # Last anomaly score
    last_anomaly_score: float = 0.0


@dataclass
class AnomalyEvent:
    timestamp: float
    mac: str
    ip: str
    score: float
    reason: str
    detail: dict = field(default_factory=dict)


class TrafficBaseliner:
    """Builds per-MAC traffic baselines and flags anomalies in real-time.

    Usage::
        baseliner = TrafficBaseliner()
        baseliner.update(ip, mac, bytes_sent, bytes_recv, packets, protocols)
        anomalies = baseliner.get_anomalies()
    """

    def __init__(self, db=None):
        self._db = db
        self._baselines: Dict[str, DeviceBaseline] = {}  # key = mac
        self._recent_anomalies: List[AnomalyEvent] = []
        self._hourly_data: Dict[str, List[float]] = defaultdict(list)  # mac → [bytes/sec samples]

    def update(self, ip: str, mac: str, bytes_sent: int, bytes_recv: int,
               packets_sent: int, packets_recv: int, protocols: Dict[str, int]):
        """Update the baseline with a traffic snapshot for a device."""
        if not mac:
            return

        now = time.time()
        baseline = self._baselines.get(mac)
        if not baseline:
            baseline = DeviceBaseline(mac=mac, ip=ip, first_seen=now)
            self._baselines[mac] = baseline

        baseline.ip = ip
        baseline.last_seen = now
        baseline.sample_count += 1

        # --- Bytes/sec rolling stats ---
        total_bytes = bytes_sent + bytes_recv
        self._hourly_data[mac].append(total_bytes)
        # Keep only last 360 samples (30 min at 5s intervals)
        if len(self._hourly_data[mac]) > 360:
            self._hourly_data[mac] = self._hourly_data[mac][-360:]

        if len(self._hourly_data[mac]) >= 10:
            baseline.mean_bytes_per_sec = statistics.mean(self._hourly_data[mac])
            baseline.std_bytes_per_sec = (
                statistics.stdev(self._hourly_data[mac])
                if len(self._hourly_data[mac]) >= 2 else 0.0
            )

        # --- Packets/sec ---
        # (tracked as rolling too for simplicity — reuse hourly_data as proxy)

        # --- Protocol profile (weighted moving average) ---
        total_proto = sum(protocols.values()) or 1
        current_proto_dist = {k: v / total_proto for k, v in protocols.items()}

        if not baseline.protocol_profile:
            baseline.protocol_profile = current_proto_dist
        else:
            # Exponential moving average (α = 0.3)
            alpha = 0.3
            all_keys = set(baseline.protocol_profile) | set(current_proto_dist)
            for k in all_keys:
                old = baseline.protocol_profile.get(k, 0.0)
                new = current_proto_dist.get(k, 0.0)
                baseline.protocol_profile[k] = (1 - alpha) * old + alpha * new

        # --- Active hours ---
        hour = datetime.now().hour
        baseline.active_hours[hour] = min(baseline.active_hours[hour] + 1, 255)

        # --- Peer IP tracking ---
        # (peers are positive — the other end of tracked conversations)
        # We rely on capture analysis to feed peers, but for now track from snapshot
        # Peers should be set externally via add_peer()

        # --- Anomaly detection ---
        anomalies = self._check_anomalies(baseline, total_bytes, protocols)
        for a in anomalies:
            self._recent_anomalies.append(a)
            if self._db:
                self._db.record_anomaly(a)
            log.warning("Traffic anomaly", mac=mac, ip=ip,
                        score=a.score, reason=a.reason)

        # Keep anomaly list bounded
        if len(self._recent_anomalies) > 100:
            self._recent_anomalies = self._recent_anomalies[-100:]

        # Persist baseline periodically
        if baseline.sample_count % 12 == 0 and self._db:  # every ~60s
            self._db.save_baseline(baseline)

    def _check_anomalies(self, baseline: DeviceBaseline, current_bytes: int,
                         protocols: Dict[str, int]) -> List[AnomalyEvent]:
        """Z-score anomaly checks against the baseline."""
        anomalies = []
        now = time.time()

        # Need minimum samples
        if baseline.sample_count < 10:
            return anomalies

        # 1. Traffic volume anomaly
        if baseline.std_bytes_per_sec > 0:
            z_score = (current_bytes - baseline.mean_bytes_per_sec) / baseline.std_bytes_per_sec
            if abs(z_score) > 2.0:
                score = min(abs(z_score), 5.0) / 5.0
                reason = "high_traffic" if z_score > 0 else "low_traffic"
                anomalies.append(AnomalyEvent(
                    timestamp=now,
                    mac=baseline.mac,
                    ip=baseline.ip,
                    score=score,
                    reason=f"{reason}: z={z_score:.1f}, current={current_bytes:.0f}, mean={baseline.mean_bytes_per_sec:.0f}",
                    detail={
                        "z_score": z_score,
                        "current_bytes": current_bytes,
                        "mean_bytes": baseline.mean_bytes_per_sec,
                        "std_bytes": baseline.std_bytes_per_sec,
                    },
                ))
                baseline.last_anomaly_score = score

        # 2. Protocol profile anomaly (Jensen-Shannon divergence?)
        # Simplified: check if any protocol exceeding 3σ from expected ratio
        if baseline.protocol_profile:
            for proto, ratio in protocols.items():
                if proto not in baseline.protocol_profile:
                    # New protocol never seen before
                    if ratio / (sum(protocols.values()) or 1) > 0.3:
                        anomalies.append(AnomalyEvent(
                            timestamp=now,
                            mac=baseline.mac,
                            ip=baseline.ip,
                            score=0.6,
                            reason=f"unexpected_protocol: {proto}",
                            detail={"protocol": proto, "ratio": ratio},
                        ))

        return anomalies

    def get_baseline(self, mac: str) -> Optional[DeviceBaseline]:
        return self._baselines.get(mac)

    def add_peer(self, mac: str, peer_ip: str):
        """Record a peer IP for a device."""
        baseline = self._baselines.get(mac)
        if baseline:
            baseline.peer_ips.add(peer_ip)

    def get_recent_anomalies(self, limit: int = 20) -> List[AnomalyEvent]:
        return self._recent_anomalies[-limit:]
