"""Application configuration via pydantic-settings (.env + env vars)."""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from typing import List
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
    cors_origins: List[str] = ["*"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v):
        if isinstance(v, str):
            # Comma-separated from env file
            return [s.strip() for s in v.split(",")]
        if isinstance(v, list):
            return v
        return ["*"]

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

    # Auth (Phase 2)
    jwt_secret: str = "netvision-dev-secret-change-in-prod"
    jwt_algorithm: str = "HS256"
    jwt_expiry_hours: int = 24

    @property
    def config_dir(self) -> str:
        return os.path.dirname(os.path.abspath(__file__))

    @property
    def database_path_abs(self) -> str:
        if os.path.isabs(self.database_path):
            return self.database_path
        return os.path.join(self.config_dir, self.database_path)


settings = Settings()
