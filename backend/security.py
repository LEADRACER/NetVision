"""NetVision Security — security headers middleware + pydantic input validation models.

Provides:
- SecurityHeadersMiddleware (HSTS, CSP, XFO, XCTO, Referrer-Policy, etc.)
- Pydantic models for validated API inputs (ScanTarget, PortRange, CaptureRequest, etc.)
- SSRF prevention via target validation
"""

import re
import ipaddress
from typing import Optional, List, Union
from enum import Enum

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field, field_validator, model_validator
from loguru import logger

from config import settings

log = logger.bind(component="security")

# ── Security Headers Middleware ──────────────────────────────────────────


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply security hardening headers to every response."""

    # Default security headers
    HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": (
            "camera=(), microphone=(), geolocation=(), interest-cohort=()"
        ),
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
    }

    # HSTS only if HTTPS (detected via X-Forwarded-Proto or scheme)
    HSTS_HEADER = "max-age=63072000; includeSubDomains; preload"

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Apply security headers
        for header, value in self.HEADERS.items():
            response.headers[header] = value

        # HSTS if served over HTTPS
        scheme = request.headers.get("X-Forwarded-Proto", request.url.scheme)
        if scheme == "https":
            response.headers["Strict-Transport-Security"] = self.HSTS_HEADER

        return response


# ── Input Validation Models ──────────────────────────────────────────────


class ScanProfile(str, Enum):
    STEALTH = "stealth"
    DEEP = "deep"
    FULL = "full"
    VULN = "vuln"
    DISCOVERY = "discovery"
    CUSTOM = "custom"


class ScanTargetValidation(BaseModel):
    """Validated scan request body/params."""

    target: Optional[str] = Field(
        None,
        description="Target IP, CIDR, or hostname. Omit for local subnet.",
        max_length=255,
    )
    profile: ScanProfile = Field(default=ScanProfile.DEEP)
    duration: Optional[int] = Field(
        None, ge=1, le=3600,
        description="Scan duration in seconds (max 1 hour)",
    )
    trace_hops: bool = Field(default=False)
    ports: Optional[str] = Field(
        None,
        pattern=r"^(\d+(-\d+)?)(,\d+(-\d+)?)*$",
        description="Port range: '22', '80,443', '1-1024', or '1-65535'",
        max_length=255,
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: Optional[str]) -> Optional[str]:
        """Validate and sanitize target input. Prevent SSRF."""
        if v is None:
            return None

        v = v.strip()

        # Check if it's an IP or CIDR
        try:
            network = ipaddress.ip_network(v, strict=False)
            if not settings.allow_private_targets:
                if network.is_private:
                    raise ValueError(
                        f"Scanning private IP ranges is disabled by default. "
                        f"Set ALLOW_PRIVATE_TARGETS=true to enable."
                    )
                if network.is_loopback:
                    raise ValueError("Scanning loopback addresses is not allowed.")
                if network.is_link_local:
                    raise ValueError("Scanning link-local addresses is not allowed.")
                if network.is_multicast:
                    raise ValueError("Scanning multicast addresses is not allowed.")

            # Enforce max hosts
            num_hosts = network.num_addresses
            if num_hosts > settings.max_scan_targets:
                raise ValueError(
                    f"Target range too large: {num_hosts} hosts "
                    f"(max: {settings.max_scan_targets})"
                )
        except ValueError as e:
            # Re-raise validation errors with context
            if "is not allowed" in str(e) or "disabled" in str(e) or "too large" in str(e):
                raise
            # Not an IP — could be hostname or something else
            # Basic hostname validation
            hostname_pattern = re.compile(
                r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
            )
            if not hostname_pattern.match(v):
                raise ValueError(f"Invalid target format: {v}")

            # Block hostnames that look like SSRF targets
            blocked_hostnames = {"localhost", "127.0.0.1", "0.0.0.0", "0", "1", "metadata"}
            if v.lower() in blocked_hostnames or v.startswith("169.254"):
                raise ValueError(f"Target not allowed: {v}")

        return v


class CaptureRequestValidation(BaseModel):
    """Validated capture request body."""

    ip: str = Field(
        ...,
        description="Target IP address for packet capture",
        max_length=45,  # IPv6 max
    )
    duration: int = Field(
        default=10, ge=5, le=300,
        description="Capture duration in seconds (5-300)",
    )

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Ensure capture target is a valid IP."""
        try:
            ip_obj = ipaddress.ip_address(v.strip())
            if not settings.allow_private_targets:
                if ip_obj.is_private:
                    raise ValueError(
                        f"Capturing private IPs is disabled. "
                        f"Set ALLOW_PRIVATE_TARGETS=true to enable."
                    )
                if ip_obj.is_loopback:
                    raise ValueError("Cannot capture loopback address.")
        except ValueError as e:
            if "disabled" in str(e) or "not allowed" in str(e):
                raise
            raise ValueError(f"Invalid IP address: {v}")
        return v.strip()


class ProbeTargetValidation(BaseModel):
    """Validated probe target."""

    ip: str = Field(
        ..., max_length=45,
        description="Target IP address",
    )
    port: int = Field(
        ..., ge=1, le=65535,
        description="Target port (1-65535)",
    )
    protocol: str = Field(
        default="tcp", pattern=r"^(tcp|udp)$",
        description="Protocol: tcp or udp",
    )

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v.strip())
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v.strip()


class LoginRequest(BaseModel):
    """Login credentials."""

    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class TokenRefreshRequest(BaseModel):
    """Refresh token request."""

    refresh_token: str = Field(..., min_length=1)


# ── Utility: check if request needs validation ───────────────────────────


def should_validate(path: str) -> bool:
    """Determine if a path has parameter validation built in."""
    # Paths that use pydantic models for validation already
    validated_paths = {
        "/capture",
    }
    if path in validated_paths:
        return True
    # Prefix matches
    if path.startswith("/probes/scan/") or path.startswith("/geolocation/"):
        return False  # These use path params validated by FastAPI
    return True
