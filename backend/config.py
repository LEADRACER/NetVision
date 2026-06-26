"""Application configuration via pydantic-settings (.env + env vars)."""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, Field
from typing import List, Dict
import os


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # CORS — accepts JSON array or comma-separated string
    cors_origins: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v):
        if isinstance(v, str):
            # Comma-separated from env file
            return [s.strip() for s in v.split(",")]
        if isinstance(v, list):
            return v
        return ["http://localhost:5173"]

    # Storage
    database_path: str = "netvision.db"
    captures_dir: str = "captures"
    reports_dir: str = "reports"
    logs_dir: str = "logs"

    # Capture
    capture_interface: str = "wlan0"

    # Scanning
    scanner_concurrency: int = 16
    scanner_default_profile: str = "deep"

    # Health monitoring
    health_check_interval: int = 30  # seconds
    health_ping_count: int = 3
    health_ping_interval: float = 0.2  # seconds between pings

    # Geolocation
    geo_cache_ttl: int = 86400  # 24h

    # Logging
    log_level: str = "INFO"
    log_json: bool = True
    log_console: bool = True

    # ── Phase 5: Data Retention ─────────────────────────────────────────
    prune_health_days: int = 90        # Health metrics retention in days
    prune_audit_days: int = 30         # Audit log retention in days
    prune_capture_days: int = 7        # Capture file retention in days

    # ── Phase 2: Auth & API Security ──────────────────────────────────────
    jwt_secret: str = "netvision-dev-secret-change-in-prod"
    jwt_expire_seconds: int = 3600          # 1 hour for access tokens
    jwt_refresh_expire_seconds: int = 604800  # 7 days for refresh

    # Built-in admin login
    auth_username: str = "admin"
    auth_password: str = "netvision"

    # API keys (env: API_KEYS='{"key1":"user1","key2":"user2"}')
    api_keys: Dict[str, str] = {}

    @field_validator("api_keys", mode="before")
    @classmethod
    def parse_api_keys(cls, v):
        if isinstance(v, str):
            import json
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return {}
        if isinstance(v, dict):
            return v
        return {}

    @property
    def jwt_secret_is_default(self) -> bool:
        """Check if JWT secret is the dev default (not production-ready)."""
        return self.jwt_secret == "netvision-dev-secret-change-in-prod"

    # ── Phase 2: Rate Limiting ────────────────────────────────────────────
    rate_limit_max_requests: int = 60       # max requests per IP per window
    rate_limit_window_seconds: int = 60     # sliding window duration
    rate_limit_scan_burst: int = 3          # max scan starts per IP per hour
    rate_limit_scan_window: int = 3600      # scan rate window (1 hour)

    # ── Phase 2: Input Validation ─────────────────────────────────────────
    allow_private_targets: bool = False     # Block scanning of RFC1918 addresses by default
    allowed_target_patterns: str = ""       # Comma-separated CIDR whitelist (empty = all public IPs)
    max_scan_targets: int = 256             # Max hosts per scan

    @property
    def config_dir(self) -> str:
        return os.path.dirname(os.path.abspath(__file__))

    @property
    def database_path_abs(self) -> str:
        if os.path.isabs(self.database_path):
            return self.database_path
        return os.path.join(self.config_dir, self.database_path)


settings = Settings()
