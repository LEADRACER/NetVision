"""Protocol decoder — HTTP request/response, DNS queries, TLS handshake, DHCP.

Extracts structured information from packet summaries by parsing the raw
tshark JSON fields. Designed to work alongside ``packet_analyzer.py`` —
decoder callbacks attach to the analyzer's packet stream.
"""

import math
import time
import collections
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable
from datetime import datetime

from loguru import logger

log = logger.bind(component="protocol_decoder")

# DNS tunneling entropy threshold
DNS_TUNNEL_ENTROPY_THRESHOLD = 0.75


@dataclass
class HttpRequest:
    timestamp: float
    src_ip: str
    dst_ip: str
    method: str = ""
    uri: str = ""
    host: str = ""
    user_agent: str = ""
    full_url: str = ""


@dataclass
class HttpResponse:
    timestamp: float
    src_ip: str
    dst_ip: str
    status_code: int = 0
    content_type: str = ""


@dataclass
class DnsQuery:
    timestamp: float
    src_ip: str
    dst_ip: str
    query_name: str = ""
    query_type: str = ""
    is_response: bool = False


@dataclass
class TlsHandshake:
    timestamp: float
    src_ip: str
    dst_ip: str
    cipher_suite: str = ""
    sni: str = ""
    version: str = ""


@dataclass
class DhcpMessage:
    timestamp: float
    src_mac: str = ""
    hostname: str = ""
    vendor_class: str = ""
    requested_ip: str = ""


@dataclass
class DecodedFlow:
    """Aggregated per-device protocol information."""
    ip: str
    http_requests: List[HttpRequest] = field(default_factory=list)
    http_responses: List[HttpResponse] = field(default_factory=list)
    dns_queries: List[DnsQuery] = field(default_factory=list)
    tls_handshakes: List[TlsHandshake] = field(default_factory=list)
    dhcp_messages: List[DhcpMessage] = field(default_factory=list)
    suspicious_dns: List[dict] = field(default_factory=list)


class ProtocolDecoder:
    """Decodes protocol-specific data from raw tshark JSON layer fields.

    Attach to ``StreamingPacketAnalyzer.on_packet()`` to get real-time
    protocol decoding alongside the main analysis pipeline.
    """

    def __init__(self, db=None):
        self._db = db
        self._flows: Dict[str, DecodedFlow] = {}
        self._decoded_callbacks: List[Callable] = []

        # DNS tunnel detection
        self._dns_state: Dict[str, dict] = collections.defaultdict(lambda: {
            "count": 0, "names": [], "entropies": [],
        })

    def on_decoded(self, callback: Callable):
        """Register callback for decoded protocol events."""
        self._decoded_callbacks.append(callback)

    def decode_packet(self, pkt_summary, raw_layers: dict):
        """Main entry — decode protocol data from a packet's layer fields.

        Args:
            pkt_summary: ``PacketSummary`` from packet_analyzer.
            raw_layers: Raw tshark JSON ``_source.layers`` dict.
        """
        self._decode_http(pkt_summary, raw_layers)
        self._decode_dns(pkt_summary, raw_layers)
        self._decode_tls(pkt_summary, raw_layers)
        self._decode_dhcp(pkt_summary, raw_layers)

    # ── HTTP Decoding ────────────────────────────────────────────────────────

    def _decode_http(self, pkt, layers: dict):
        method = self._get_first(layers, "http.request.method")
        if method:
            req = HttpRequest(
                timestamp=pkt.timestamp,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                method=method,
                uri=self._get_first(layers, "http.request.uri") or "",
                host=self._get_first(layers, "http.host") or "",
            )
            self._store_decoded(pkt.src_ip, "http_requests", req)
            self._fire("http_request", req)
            if self._db:
                self._db.record_http_log(req)

        status = self._get_first(layers, "http.response.code")
        if status:
            resp = HttpResponse(
                timestamp=pkt.timestamp,
                src_ip=pkt.dst_ip,
                dst_ip=pkt.src_ip,
                status_code=int(status),
            )
            self._store_decoded(pkt.dst_ip, "http_responses", resp)
            self._fire("http_response", resp)
            if self._db:
                self._db.record_http_log(resp)

    # ── DNS Decoding ─────────────────────────────────────────────────────────

    def _decode_dns(self, pkt, layers: dict):
        qname = self._get_first(layers, "dns.qry.name")
        if qname is None:
            return

        qtype = self._get_first(layers, "dns.qry.type") or "A"
        is_resp = self._get_first(layers, "dns.flags.response") == "1"

        query = DnsQuery(
            timestamp=pkt.timestamp,
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            query_name=qname,
            query_type=qtype,
            is_response=is_resp,
        )

        # Track per-IP for tunneling detection
        if not is_resp:
            state = self._dns_state[pkt.src_ip]
            state["count"] += 1
            state["names"].append(qname)
            entropy = self._calc_entropy(qname)
            state["entropies"].append(entropy)

            if entropy > DNS_TUNNEL_ENTROPY_THRESHOLD and state["count"] > 5:
                # High entropy over multiple queries = suspicious
                sus = {
                    "ip": pkt.src_ip,
                    "dns_server": pkt.dst_ip,
                    "sample_names": state["names"][-10:],
                    "avg_entropy": sum(state["entropies"][-10:]) / min(10, len(state["entropies"])),
                    "total_queries": state["count"],
                    "timestamp": pkt.timestamp,
                }
                log.warning("DNS tunneling suspected", **sus)
                self._fire("dns_tunnel_suspect", sus)
                if self._db:
                    self._db.store_suspicious_dns(sus)
                # Reset counter to avoid repeated alerts
                state["count"] = 0

        self._store_decoded(pkt.src_ip, "dns_queries", query)
        self._fire("dns_query", query)
        if self._db:
            self._db.record_dns_log(query)

    # ── TLS Decoding ─────────────────────────────────────────────────────────

    def _decode_tls(self, pkt, layers: dict):
        cipher = self._get_first(layers, "tls.handshake.ciphersuite")
        sni = self._get_first(layers, "tls.handshake.extensions_server_name")

        if cipher or sni:
            hs = TlsHandshake(
                timestamp=pkt.timestamp,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                cipher_suite=cipher or "",
                sni=sni or "",
                version=self._get_first(layers, "tls.handshake.version") or "",
            )
            self._store_decoded(pkt.src_ip, "tls_handshakes", hs)
            self._fire("tls_handshake", hs)
            if self._db:
                self._db.record_tls_log(hs)

    # ── DHCP Decoding ────────────────────────────────────────────────────────

    def _decode_dhcp(self, pkt, layers: dict):
        hostname = self._get_first(layers, "dhcp.option.hostname")
        vendor = self._get_first(layers, "dhcp.option.vendor_id")

        if hostname or vendor:
            msg = DhcpMessage(
                timestamp=pkt.timestamp,
                src_mac=pkt.src_mac,
                hostname=hostname or "",
                vendor_class=vendor or "",
            )
            self._store_decoded(pkt.src_ip, "dhcp_messages", msg)
            self._fire("dhcp_message", msg)
            if self._db:
                self._db.record_dhcp_log(msg)

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _store_decoded(self, ip: str, field_name: str, item):
        if ip not in self._flows:
            self._flows[ip] = DecodedFlow(ip=ip)
        getattr(self._flows[ip], field_name).append(item)

        # Keep bounded
        lst = getattr(self._flows[ip], field_name)
        if len(lst) > 500:
            setattr(self._flows[ip], field_name, lst[-250:])

    def _fire(self, event: str, data):
        for cb in self._decoded_callbacks:
            try:
                cb(event, data)
            except Exception as e:
                log.debug("Decoded callback error", event=event, error=str(e))

    def get_flow(self, ip: str) -> Optional[DecodedFlow]:
        return self._flows.get(ip)

    @staticmethod
    def _calc_entropy(name: str) -> float:
        """Normalized Shannon entropy of a DNS name (0-1).
        Legitimate DNS names have low entropy; tunneled data is near-random.
        """
        if not name:
            return 0.0
        # Strip the domain suffix (e.g., .example.com) to check the subdomain
        parts = name.rstrip(".").split(".")
        if len(parts) < 2:
            return 0.0
        # Check the leftmost label (most likely to be random)
        label = parts[0]
        if not label:
            return 0.0

        freq: Dict[str, int] = {}
        for ch in label:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(label)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )
        # Normalize to 0-1 (max entropy for label length)
        max_entropy = math.log2(min(length, 62))  # 62 = alphanumeric + hyphen
        return entropy / max_entropy if max_entropy > 0 else 0.0

    @staticmethod
    def _get_first(layers: dict, key: str) -> Optional[str]:
        val = layers.get(key)
        if val is None:
            return None
        if isinstance(val, list):
            return str(val[0]) if val else None
        return str(val)
