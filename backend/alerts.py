"""NetVision alerting system — webhook dispatch to Slack, Discord, Telegram, or generic HTTP.

Provides rate-limited, deduplicated alert delivery for:
- Device going down (3+ consecutive health check failures)
- New vulnerability discovered (CVSS > 7.0)
- Scan failures / errors
- Autonomous re-scan triggers
"""

import asyncio
import json
import time
import hashlib
from typing import Optional, Dict, List, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum

from loguru import logger

log = logger.bind(component="alerts")


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertType(Enum):
    DEVICE_DOWN = "device_down"
    DEVICE_UP = "device_up"
    VULN_FOUND = "vuln_found"
    SCAN_FAILED = "scan_failed"
    SCAN_COMPLETE = "scan_complete"
    ANOMALY_DETECTED = "anomaly_detected"
    SYSTEM_ERROR = "system_error"


@dataclass
class Alert:
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    message: str
    fields: Dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def dedup_key(self) -> str:
        """Unique key for rate-limited dedup."""
        raw = f"{self.alert_type.value}:{self.title}:{json.dumps(self.fields, sort_keys=True)}"
        return hashlib.md5(raw.encode()).hexdigest()


class AlertWebhook:
    """Represents a configured webhook target."""

    def __init__(self, url: str, channel_type: str = "generic", name: str = ""):
        self.url = url
        self.channel_type = channel_type  # 'slack', 'discord', 'telegram', 'generic'
        self.name = name or channel_type

    async def send(self, alert: Alert) -> bool:
        """Dispatch alert to this webhook. Returns True on success."""
        try:
            import httpx

            payload = self._format(alert)
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self.url, json=payload)
                if resp.status_code < 400:
                    log.debug("Alert delivered", channel=self.name, alert=alert.alert_type.value)
                    return True
                else:
                    log.warning(
                        "Alert webhook returned error",
                        channel=self.name,
                        status=resp.status_code,
                        body=resp.text[:200],
                    )
                    return False
        except Exception as e:
            log.error("Alert delivery failed", channel=self.name, error=str(e))
            return False

    def _format(self, alert: Alert) -> Dict:
        """Format alert for the target platform."""
        if self.channel_type == "slack":
            color_map = {
                AlertSeverity.INFO: "#36a64f",
                AlertSeverity.WARNING: "#f2c744",
                AlertSeverity.CRITICAL: "#ef4444",
            }
            fields = []
            for key, value in alert.fields.items():
                fields.append({"title": key, "value": str(value), "short": True})
            return {
                "attachments": [
                    {
                        "color": color_map.get(alert.severity, "#36a64f"),
                        "title": alert.title,
                        "text": alert.message,
                        "fields": fields,
                        "footer": f"NetVision • {alert.severity.value}",
                        "ts": int(alert.timestamp),
                    }
                ]
            }

        elif self.channel_type == "discord":
            color_map = {
                AlertSeverity.INFO: 0x36A64F,
                AlertSeverity.WARNING: 0xF2C744,
                AlertSeverity.CRITICAL: 0xEF4444,
            }
            embed = {
                "title": alert.title,
                "description": alert.message,
                "color": color_map.get(alert.severity, 0x36A64F),
                "fields": [
                    {"name": k, "value": str(v), "inline": True}
                    for k, v in alert.fields.items()
                ],
                "footer": {"text": f"NetVision • {alert.severity.value}"},
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(alert.timestamp)),
            }
            return {"embeds": [embed]}

        elif self.channel_type == "telegram":
            text = f"*{alert.title}*\n{alert.message}\n"
            for k, v in alert.fields.items():
                text += f"`{k}`: {v}\n"
            return {
                "chat_id": self.url.split("/")[-1] if "/" in self.url else "",
                "text": text,
                "parse_mode": "Markdown",
            }

        else:  # generic JSON
            return {
                "alert_type": alert.alert_type.value,
                "severity": alert.severity.value,
                "title": alert.title,
                "message": alert.message,
                "fields": alert.fields,
                "timestamp": alert.timestamp,
            }


class AlertManager:
    """Central alert coordinator with rate limiting, dedup, and multi-channel dispatch."""

    def __init__(self):
        self.webhooks: List[AlertWebhook] = []
        self._dedup_cache: Dict[str, float] = {}  # dedup_key -> timestamp
        self._rate_limit_window: float = 30.0  # seconds — same alert suppressed within window
        self._alert_history: List[Alert] = []
        self._max_history: int = 1000

    def add_webhook(self, webhook: AlertWebhook):
        """Register a webhook channel."""
        self.webhooks.append(webhook)
        log.info("Alert webhook registered", channel=webhook.name, type=webhook.channel_type)

    def remove_webhook(self, name: str) -> bool:
        """Remove a webhook by name."""
        before = len(self.webhooks)
        self.webhooks = [w for w in self.webhooks if w.name != name]
        return len(self.webhooks) < before

    def is_duplicate(self, alert: Alert) -> bool:
        """Check if this alert was sent recently (rate-limited dedup)."""
        key = alert.dedup_key
        now = time.time()
        last_sent = self._dedup_cache.get(key)
        if last_sent and (now - last_sent) < self._rate_limit_window:
            return True
        self._dedup_cache[key] = now
        # Prune old entries periodically
        if len(self._dedup_cache) > 1000:
            cutoff = now - 300  # 5 min
            self._dedup_cache = {k: v for k, v in self._dedup_cache.items() if v > cutoff}
        return False

    async def send_alert(self, alert: Alert) -> int:
        """Dispatch an alert to all registered webhooks. Returns number of successful deliveries."""
        if self.is_duplicate(alert):
            log.debug("Alert suppressed (duplicate)", alert=alert.alert_type.value)
            return 0

        # Record history
        self._alert_history.append(alert)
        if len(self._alert_history) > self._max_history:
            self._alert_history = self._alert_history[-self._max_history:]

        if not self.webhooks:
            log.debug("No webhooks configured — alert logged only", alert=alert.alert_type.value)
            return 0

        tasks = [webhook.send(alert) for webhook in self.webhooks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = sum(1 for r in results if r is True)
        fail_count = sum(1 for r in results if r is False)

        if fail_count > 0:
            from metrics import ALERT_FAILURES, ALERTS_SENT
            for i, result in enumerate(results):
                if result is False:
                    ALERT_FAILURES.labels(channel=self.webhooks[i].channel_type).inc()

        from metrics import ALERTS_SENT
        ALERTS_SENT.labels(type=alert.alert_type.value, channel="all").inc(success_count)

        return success_count

    async def alert_device_down(self, ip: str, device_name: str, latency: float, consecutive_failures: int):
        """Alert that a device has gone down."""
        await self.send_alert(Alert(
            alert_type=AlertType.DEVICE_DOWN,
            severity=AlertSeverity.CRITICAL,
            title=f"🔴 Device Down: {ip}",
            message=f"{device_name or ip} has stopped responding to health checks.",
            fields={
                "IP": ip,
                "Device": device_name or "Unknown",
                "Last Latency": f"{latency:.1f}ms" if latency else "N/A",
                "Consecutive Failures": str(consecutive_failures),
            },
        ))

    async def alert_device_up(self, ip: str, device_name: str, latency: float):
        """Alert that a device has recovered."""
        await self.send_alert(Alert(
            alert_type=AlertType.DEVICE_UP,
            severity=AlertSeverity.INFO,
            title=f"🟢 Device Recovered: {ip}",
            message=f"{device_name or ip} is back online.",
            fields={
                "IP": ip,
                "Device": device_name or "Unknown",
                "Latency": f"{latency:.1f}ms" if latency else "N/A",
            },
        ))

    async def alert_vuln_found(self, ip: str, cve_id: str, cvss: float, description: str):
        """Alert on a high-severity vulnerability."""
        severity = AlertSeverity.CRITICAL if cvss >= 9.0 else AlertSeverity.WARNING
        await self.send_alert(Alert(
            alert_type=AlertType.VULN_FOUND,
            severity=severity,
            title=f"⚠️ Vulnerability: {cve_id} (CVSS {cvss})",
            message=description[:200],
            fields={
                "IP": ip,
                "CVE": cve_id,
                "CVSS": f"{cvss}/10",
                "Severity": "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM",
            },
        ))

    async def alert_scan_failed(self, target: str, error: str):
        """Alert that a scan failed."""
        await self.send_alert(Alert(
            alert_type=AlertType.SCAN_FAILED,
            severity=AlertSeverity.WARNING,
            title=f"⚠️ Scan Failed: {target}",
            message=f"Scan of {target} encountered an error.",
            fields={"Target": target, "Error": error[:200]},
        ))


# Singleton
alert_manager = AlertManager()
