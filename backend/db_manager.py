"""NetVision database connection management.

Production-grade SQLite connection context manager.
Every connection gets tuned PRAGMAs for safety, concurrency, and durability.
"""

import sqlite3
from contextlib import contextmanager
from typing import Iterator, Optional, Any
from loguru import logger

# ── Production PRAGMAs applied to every connection ───────────────────────
#
# WAL mode:    Allows concurrent reads while writes are happening.
#              Far better performance under mixed read/write workloads.
#
# foreign_keys: Required for referential integrity. SQLite defaults to OFF.
#
# busy_timeout: Instead of returning "database is locked" immediately,
#               the connection busy-waits for the lock up to 5 seconds.
#
# synchronous=NORMAL: In WAL mode, NORMAL is safe and ~2x faster than FULL.
#                     WAL checkpoint takes over crash recovery.
#
# journal_size_limit: Prevent journal from growing unboundedly under WAL.
#
# cache_size:   Raise page cache from default 2MB to 64MB for scan-heavy loads.

PRODUCTION_PRAGMAS = [
    ("PRAGMA journal_mode=WAL", False),
    ("PRAGMA foreign_keys=ON", False),
    ("PRAGMA busy_timeout=5000", False),
    ("PRAGMA synchronous=NORMAL", False),
    ("PRAGMA journal_size_limit=67108864", False),   # 64 MB
    ("PRAGMA cache_size=-64000", False),              # 64 MB page cache
    ("PRAGMA temp_store=MEMORY", False),
]


@contextmanager
def connect(db_path: str, *, timeout: int = 5, row_factory: bool = False) -> Iterator[sqlite3.Connection]:
    """Get a production-tuned SQLite connection for read/write operations.

    Usage:
        with connect("/path/to/db.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices")
            conn.commit()

    Sets all PRAGMAs listed above on every connection.
    The connection is always closed when the block exits.

    Args:
        db_path: Absolute or relative path to the SQLite database file.
        timeout: Connection busy timeout in seconds (default 5).
        row_factory: If True, sets sqlite3.Row as the row factory for
                     dict-compatible fetches.

    Yields:
        sqlite3.Connection with production PRAGMAs applied.
    """
    conn = sqlite3.connect(db_path, timeout=timeout)

    if row_factory:
        conn.row_factory = sqlite3.Row

    # Apply PRAGMAs
    for pragma_sql, is_quiet in PRODUCTION_PRAGMAS:
        try:
            conn.execute(pragma_sql)
        except Exception as exc:
            if not is_quiet:
                logger.bind(component="database").warning(
                    "PRAGMA failed", pragma=pragma_sql, error=str(exc)
                )

    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def connect_row(db_path: str, *, timeout: int = 5) -> Iterator[sqlite3.Connection]:
    """Shortcut: get connection with row_factory pre-configured.

    Usage:
        with connect_row("/path/to/db.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ...")
            rows = [dict(r) for r in cursor.fetchall()]
    """
    with connect(db_path, timeout=timeout, row_factory=True) as conn:
        yield conn
