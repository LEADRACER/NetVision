"""NetVision Rate Limiter — token-bucket per IP with scan-specific throttling.

Provides:
- Per-IP sliding window rate limiter for general API calls
- Per-IP scan start throttling (prevents hammering the scanner)
- FastAPI middleware integration
"""

import time
from collections import defaultdict
from typing import Dict, Tuple, Optional

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from loguru import logger

from config import settings

log = logger.bind(component="rate_limiter")


class SlidingWindowRateLimiter:
    """Sliding window counter per IP address."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._windows: Dict[str, list] = defaultdict(list)  # ip -> [timestamp, ...]

    def check(self, ip: str) -> Tuple[bool, int, int]:
        """Check if IP is within rate limit.

        Returns: (allowed: bool, current_count: int, remaining: int)
        """
        now = time.time()
        cutoff = now - self.window_seconds

        # Prune old entries
        window = self._windows[ip]
        while window and window[0] < cutoff:
            window.pop(0)

        current_count = len(window)
        remaining = max(0, self.max_requests - current_count)

        if current_count >= self.max_requests:
            return False, current_count, remaining

        # Record this request
        window.append(now)
        return True, current_count, remaining

    def reset(self, ip: str) -> None:
        """Reset rate limit counter for an IP."""
        self._windows.pop(ip, None)

    def get_remaining(self, ip: str) -> int:
        """Get remaining requests for this IP."""
        now = time.time()
        cutoff = now - self.window_seconds
        window = self._windows.get(ip, [])
        while window and window[0] < cutoff:
            window.pop(0)
        return max(0, self.max_requests - len(window))


class ScanRateLimiter:
    """Separate rate limiter specifically for scan starts.

    Prevents one IP from saturating the scanner queue.
    """

    def __init__(self, max_burst: int, window_seconds: int):
        self.max_burst = max_burst
        self.window_seconds = window_seconds
        self._scans: Dict[str, list] = defaultdict(list)  # ip -> [timestamp, ...]

    def can_start_scan(self, ip: str) -> Tuple[bool, int]:
        """Check if IP is allowed to start a scan.

        Returns: (allowed: bool, retry_after_seconds: int)
        """
        now = time.time()
        cutoff = now - self.window_seconds
        window = self._scans[ip]

        # Prune old
        while window and window[0] < cutoff:
            window.pop(0)

        if len(window) >= self.max_burst:
            retry_after = int(window[0] + self.window_seconds - now)
            return False, max(1, retry_after)

        window.append(now)
        return True, 0


# ── Rate Limiter Middleware ─────────────────────────────────────────────


API_RATE_LIMITER = SlidingWindowRateLimiter(
    max_requests=settings.rate_limit_max_requests,
    window_seconds=settings.rate_limit_window_seconds,
)

SCAN_RATE_LIMITER = ScanRateLimiter(
    max_burst=settings.rate_limit_scan_burst,
    window_seconds=settings.rate_limit_scan_window,
)

# Paths excluded from rate limiting
RATE_LIMIT_EXEMPT_PATHS = {
    "/health",
    "/health/live",
    "/health/ready",
    "/metrics",
    "/favicon.ico",
}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply sliding-window rate limiting per IP on all non-exempt routes."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip exempt paths
        if path in RATE_LIMIT_EXEMPT_PATHS:
            return await call_next(request)

        # Get client IP (respect X-Forwarded-For if behind proxy)
        client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
        client_ip = client_ip.split(",")[0].strip()

        allowed, count, remaining = API_RATE_LIMITER.check(client_ip)
        if not allowed:
            log.warning(
                f"Rate limit exceeded for {client_ip} on {path}",
                extra={"component": "auth", "client_ip": client_ip, "path": path, "count": count},
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Rate limit exceeded",
                    "retry_after_seconds": API_RATE_LIMITER.window_seconds,
                    "limit": API_RATE_LIMITER.max_requests,
                },
            )

        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(API_RATE_LIMITER.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(time.time() + API_RATE_LIMITER.window_seconds))

        return response


def check_scan_rate_limit(request: Request) -> None:
    """Check scan rate limit. Called explicitly in scan endpoint handler.

    Raises 429 if exceeded.
    """
    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
    client_ip = client_ip.split(",")[0].strip()

    allowed, retry_after = SCAN_RATE_LIMITER.can_start_scan(client_ip)
    if not allowed:
        log.warning(
            f"Scan rate limit exceeded for {client_ip}",
            extra={"component": "auth", "client_ip": client_ip, "retry_after": retry_after},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Scan rate limit exceeded",
                "retry_after_seconds": retry_after,
                "limit": f"{SCAN_RATE_LIMITER.max_burst} scans per {SCAN_RATE_LIMITER.window_seconds}s",
            },
        )
