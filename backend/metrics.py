"""NetVision Prometheus metrics — request rates, scan durations, probe success, health status."""

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import time

# ── HTTP request tracking ────────────────────────────────────────────────

HTTP_REQUEST_COUNT = Counter(
    "netvision_http_requests_total",
    "Total HTTP requests by method and path",
    ["method", "path", "status"],
)

HTTP_REQUEST_LATENCY = Histogram(
    "netvision_http_request_duration_ms",
    "HTTP request latency in milliseconds",
    ["method", "path"],
    buckets=(5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000),
)

# ── Scanner metrics ──────────────────────────────────────────────────────

SCAN_DURATION = Histogram(
    "netvision_scan_duration_seconds",
    "Duration of network scans",
    ["profile"],
    buckets=(5, 10, 30, 60, 120, 300, 600, 1800, 3600),
)

SCAN_DEVICES_FOUND = Histogram(
    "netvision_scan_devices_found",
    "Devices found per scan",
    ["profile"],
    buckets=(1, 5, 10, 25, 50, 100, 250, 500),
)

SCANS_IN_PROGRESS = Gauge(
    "netvision_scans_in_progress",
    "Number of scans currently running",
)

SCANS_TOTAL = Counter(
    "netvision_scans_total",
    "Total scans started",
    ["profile"],
)

# ── Probe / service metrics ──────────────────────────────────────────────

PROBE_ATTEMPTS = Counter(
    "netvision_probe_attempts_total",
    "Total service probe attempts",
    ["service", "port"],
)

PROBE_SUCCESS = Counter(
    "netvision_probe_success_total",
    "Successful service probes",
    ["service"],
)

PROBE_FAILURES = Counter(
    "netvision_probe_failures_total",
    "Failed service probes",
    ["service"],
)

# ── Health monitor metrics ───────────────────────────────────────────────

HEALTH_DEVICES_UP = Gauge(
    "netvision_health_devices_up",
    "Number of devices currently up",
)

HEALTH_DEVICES_DOWN = Gauge(
    "netvision_health_devices_down",
    "Number of devices currently down",
)

HEALTH_CHECK_DURATION = Histogram(
    "netvision_health_check_duration_ms",
    "Health check ping latency in milliseconds",
    ["device_ip"],
    buckets=(1, 5, 10, 25, 50, 100, 250, 500, 1000),
)

# ── Packet capture metrics ───────────────────────────────────────────────

CAPTURE_PACKETS = Counter(
    "netvision_capture_packets_total",
    "Total packets captured",
    ["ip"],
)

CAPTURE_BYTES = Counter(
    "netvision_capture_bytes_total",
    "Total bytes captured",
    ["ip"],
)

# ── Alert metrics ────────────────────────────────────────────────────────

ALERTS_SENT = Counter(
    "netvision_alerts_sent_total",
    "Total alerts dispatched",
    ["type", "channel"],
)

ALERT_FAILURES = Counter(
    "netvision_alert_failures_total",
    "Alert delivery failures",
    ["channel"],
)

# ── Database metrics ─────────────────────────────────────────────────────

DB_QUERY_DURATION = Histogram(
    "netvision_db_query_duration_ms",
    "Database query latency",
    ["operation"],
    buckets=(1, 5, 10, 25, 50, 100, 250, 500),
)

# ── Middleware for automatic request metrics ──────────────────────────────


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record HTTP request count + latency for every request."""

    async def dispatch(self, request: Request, call_next):
        method = request.method
        path = request.url.path

        # Strip dynamic segments for cardinality control
        clean_path = self._clean_path(path)

        start = time.monotonic()
        response: Response = await call_next(request)
        elapsed_ms = (time.monotonic() - start) * 1000

        HTTP_REQUEST_COUNT.labels(method=method, path=clean_path, status=response.status_code).inc()
        HTTP_REQUEST_LATENCY.labels(method=method, path=clean_path).observe(elapsed_ms)

        return response

    @staticmethod
    def _clean_path(path: str) -> str:
        """Collapse dynamic segments to keep label cardinality bounded."""
        parts = path.strip("/").split("/")
        cleaned = []
        for part in parts:
            # IP addresses → {ip}
            if part.count(".") == 3 and all(c.isdigit() or c == "." for c in part):
                cleaned.append("{ip}")
            # UUIDs → {id}
            elif len(part) == 36 and part.count("-") == 4:
                cleaned.append("{id}")
            # Numeric IDs → {id}
            elif part.isdigit():
                cleaned.append("{id}")
            else:
                cleaned.append(part)
        return "/" + "/".join(cleaned)


# ── Expose endpoint ──────────────────────────────────────────────────────


async def metrics_endpoint():
    """GET /metrics — Prometheus scrape endpoint."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
