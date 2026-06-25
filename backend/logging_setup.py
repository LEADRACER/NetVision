"""Loguru-based structured logging setup.

Provides console output + rotated JSON files per component.
Correlation IDs are injected via the middleware context var.
"""

import sys
import os
from loguru import logger
from contextvars import ContextVar

request_id_var: ContextVar[str] = ContextVar("request_id", default="")


def component_file_sink(component: str, logs_dir: str):
    """Rotating JSON log file for a specific component."""
    os.makedirs(logs_dir, exist_ok=True)
    path = os.path.join(logs_dir, f"{component}.log.jsonl")
    return logger.add(
        path,
        filter=lambda record: record["extra"].get("component") == component,
        rotation="10 MB",
        retention="30 days",
        level="DEBUG",
        serialize=True,
    )


def setup_logging(settings):
    """Configure all logging sinks."""
    logs_dir = os.path.join(settings.config_dir, settings.logs_dir)
    os.makedirs(logs_dir, exist_ok=True)

    # Remove default handler
    logger.remove()

    # Console — human-readable, colored
    if settings.log_console:
        def console_format(record):
            comp = record["extra"].get("component", "main")
            rid = record["extra"].get("request_id", "")
            rid_part = f" [{rid[:8]}]" if rid else ""
            return (
                f"<level>{record['level'].name: <8}</level> "
                f"| <cyan>{comp: <8}</cyan> "
                f"| <level>{record['message']}</level>{rid_part}\n"
            )

        logger.add(
            sys.stderr,
            format=console_format,
            level=settings.log_level,
            colorize=True,
        )
    # Main JSON log — everything serialized
    main_log = os.path.join(logs_dir, "netvision.jsonl")
    logger.add(
        main_log,
        rotation="25 MB",
        retention="60 days",
        level="DEBUG",
        serialize=True,
    )

    # Per-component JSON files
    for c in ("api", "scanner", "health", "probes", "capture", "geo", "database", "reports"):
        component_file_sink(c, logs_dir)

    # Errors-only log
    error_log = os.path.join(logs_dir, "errors.jsonl")
    logger.add(
        error_log,
        level="ERROR",
        rotation="50 MB",
        retention="90 days",
        serialize=True,
    )

    logger.info("Logging initialized", extra={"component": "system"})
