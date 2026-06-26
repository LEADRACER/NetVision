"""NetVision database — SQLite + db_manager connection management.

Every connection is managed via the `_get_conn()` context manager which
applies production PRAGMAs (WAL, foreign_keys, busy_timeout, etc.).
All 35+ methods use `with self._get_conn(...) as conn:` instead of
raw `sqlite3.connect()` + manual `conn.close()`.
"""

import sqlite3
import json
import datetime
import os
import time
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from loguru import logger

from db_manager import connect, connect_row


class Database:
    def __init__(self, db_path="netvision.db"):
        self.db_path = db_path
        self.init_tables()

    # ── Connection management ─────────────────────────────────────────────

    @contextmanager
    def _get_conn(self, row_factory: bool = False):
        """Get a production-tuned connection for this database.

        All PRAGMAs (WAL, foreign_keys, busy_timeout, etc.) are set
        automatically. The connection is closed when the block exits.

        Usage:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("...")
                conn.commit()
        """
        with connect(self.db_path, row_factory=row_factory) as conn:
            yield conn

    def _init_conn(self, conn: sqlite3.Connection):
        """Apply PRAGMAs once per physical connection (for long-lived uses)."""
        from db_manager import PRODUCTION_PRAGMAS
        for pragma_sql, _ in PRODUCTION_PRAGMAS:
            try:
                conn.execute(pragma_sql)
            except Exception:
                pass

    # ── Schema initialization ─────────────────────────────────────────────

    def init_tables(self):
        """Create all necessary tables if they don't exist."""
        with self._get_conn() as conn:
            cursor = conn.cursor()

            # Scans table — one row per scan job
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    target TEXT,
                    profile TEXT,
                    duration INTEGER,
                    trace_hops BOOLEAN,
                    status TEXT DEFAULT 'running',
                    total_devices INTEGER,
                    subnets_scanned INTEGER
                )
            ''')

            # Devices table — discovered hosts (one row per IP)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    ip TEXT NOT NULL,
                    mac TEXT,
                    vendor TEXT,
                    hostname TEXT,
                    os TEXT,
                    latency_ms REAL,
                    distance INTEGER,
                    hop_count INTEGER,
                    strength INTEGER,
                    vulns_detected BOOLEAN DEFAULT 0,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id),
                    UNIQUE(ip)
                )
            ''')

            # Ports table — open ports per device
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    port INTEGER,
                    protocol TEXT,
                    state TEXT,
                    service TEXT,
                    version TEXT,
                    product TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices(id),
                    UNIQUE(device_id, port, protocol)
                )
            ''')

            # Health metrics — time-series for latency, packet loss
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS health_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    latency_ms REAL,
                    packet_loss BOOLEAN DEFAULT 0,
                    status TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                )
            ''')

            # Geolocation cache — IP → location/ASN
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS geolocation (
                    ip TEXT PRIMARY KEY,
                    country TEXT,
                    region TEXT,
                    city TEXT,
                    asn TEXT,
                    org TEXT,
                    latitude REAL,
                    longitude REAL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Vulnerabilities — CVE details per device/port
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    port_id INTEGER,
                    cve_id TEXT,
                    cvss_score REAL,
                    severity TEXT,
                    description TEXT,
                    reference_urls TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id),
                    FOREIGN KEY (port_id) REFERENCES ports(id)
                )
            ''')

            # Reports — generated reports metadata
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    report_type TEXT,
                    filename TEXT,
                    scan_id INTEGER,
                    exported_by TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')

            # Audit log — every API call tracked
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    method TEXT,
                    path TEXT,
                    status INTEGER,
                    client_ip TEXT,
                    request_id TEXT,
                    user_agent TEXT,
                    elapsed_ms REAL,
                    extra TEXT
                )
            ''')

            # Scan schedules — recurring scans
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    profile TEXT NOT NULL DEFAULT 'deep',
                    interval_minutes INTEGER NOT NULL DEFAULT 60,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    requester TEXT DEFAULT 'system',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_run TIMESTAMP
                )
            """)

            # Scan results — device snapshots per scan for diffing
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    mac TEXT,
                    vendor TEXT,
                    os TEXT,
                    ports_json TEXT,
                    latency_ms REAL,
                    hop_count INTEGER,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)

            # Index for scan_results lookup
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_results_scan_ip
                ON scan_results(scan_id, ip)
            """)

            # Add origin column to scans if missing (migration pattern without alembic)
            cursor.execute("PRAGMA table_info(scans)")
            columns = [r[1] for r in cursor.fetchall()]
            if "origin" not in columns:
                cursor.execute("ALTER TABLE scans ADD COLUMN origin TEXT DEFAULT 'manual'")

            # ════════════════════════════════════════════════════════════
            # PHASE 4: PACKET CAPTURE & ANALYSIS TABLES
            # ════════════════════════════════════════════════════════════

            # Per-second traffic snapshots
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    mac TEXT DEFAULT '',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_recv INTEGER DEFAULT 0,
                    packets_sent INTEGER DEFAULT 0,
                    packets_recv INTEGER DEFAULT 0,
                    protocols TEXT DEFAULT '{}',
                    syn_rate REAL DEFAULT 0.0,
                    port_scan_score REAL DEFAULT 0.0,
                    alert_flags TEXT DEFAULT '[]'
                )
            """)

            # HTTP request/response logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS http_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    method TEXT DEFAULT '',
                    uri TEXT DEFAULT '',
                    host TEXT DEFAULT '',
                    status_code INTEGER DEFAULT 0,
                    log_type TEXT DEFAULT 'request'
                )
            """)

            # DNS query logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT DEFAULT '',
                    query_name TEXT NOT NULL,
                    query_type TEXT DEFAULT 'A',
                    is_response INTEGER DEFAULT 0
                )
            """)

            # TLS handshake logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tls_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT DEFAULT '',
                    cipher_suite TEXT DEFAULT '',
                    sni TEXT DEFAULT '',
                    version TEXT DEFAULT ''
                )
            """)

            # DHCP message logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dhcp_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    src_mac TEXT DEFAULT '',
                    hostname TEXT DEFAULT '',
                    vendor_class TEXT DEFAULT ''
                )
            """)

            # Suspicious DNS (potential tunneling)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS suspicious_dns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    dns_server TEXT DEFAULT '',
                    sample_names TEXT DEFAULT '[]',
                    avg_entropy REAL DEFAULT 0.0,
                    total_queries INTEGER DEFAULT 0
                )
            """)

            # Traffic baselines (per MAC)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_baselines (
                    mac TEXT PRIMARY KEY,
                    ip TEXT DEFAULT '',
                    first_seen REAL DEFAULT 0.0,
                    last_seen REAL DEFAULT 0.0,
                    mean_bytes_per_sec REAL DEFAULT 0.0,
                    std_bytes_per_sec REAL DEFAULT 0.0,
                    mean_packets_per_sec REAL DEFAULT 0.0,
                    std_packets_per_sec REAL DEFAULT 0.0,
                    protocol_profile TEXT DEFAULT '{}',
                    active_hours TEXT DEFAULT '[0]*24',
                    peer_ips TEXT DEFAULT '[]',
                    sample_count INTEGER DEFAULT 0,
                    last_anomaly_score REAL DEFAULT 0.0
                )
            """)

            # Anomaly events
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    mac TEXT DEFAULT '',
                    ip TEXT DEFAULT '',
                    score REAL DEFAULT 0.0,
                    reason TEXT DEFAULT '',
                    detail TEXT DEFAULT '{}'
                )
            """)

            # Rogue AP / deauth detection
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rogue_ap_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    bssid TEXT DEFAULT '',
                    ssid TEXT DEFAULT '',
                    src_mac TEXT DEFAULT '',
                    channel INTEGER DEFAULT 0,
                    rssi INTEGER DEFAULT 0,
                    detail TEXT DEFAULT ''
                )
            """)

            # Indexes for Phase 4 tables
            for table_col in [
                ("traffic_snapshots", "ip"),
                ("traffic_snapshots", "timestamp"),
                ("http_logs", "src_ip"),
                ("dns_logs", "src_ip"),
                ("dns_logs", "query_name"),
                ("tls_logs", "src_ip"),
                ("suspicious_dns", "ip"),
                ("anomaly_events", "mac"),
                ("anomaly_events", "timestamp"),
                ("rogue_ap_events", "event_type"),
            ]:
                idx_name = f"idx_{table_col[0]}_{table_col[1]}"
                cursor.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table_col[0]}({table_col[1]})")

            # Indexes for fast querying
            for table_col in [
                ("devices", "ip"),
                ("health_metrics", "timestamp"),
                ("health_metrics", "device_id"),
                ("scans", "started_at"),
                ("audit_log", "timestamp"),
                ("ports", "device_id"),
            ]:
                try:
                    cursor.execute(
                        f"CREATE INDEX IF NOT EXISTS idx_{table_col[0]}_{table_col[1]} "
                        f"ON {table_col[0]}({table_col[1]})"
                    )
                except Exception:
                    pass

            # WAL mode already applied by _get_conn() — this is belt-and-suspenders
            # for any legacy code that bypasses the context manager.
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
            except Exception:
                pass

            conn.commit()

    # ─── Audit Log ────────────────────────────────────────────────────────

    def record_audit(self, method: str, path: str, status: int,
                     client_ip: str = "", request_id: str = "",
                     user_agent: str = "", elapsed_ms: float = 0,
                     extra: str = ""):
        """Record an API access to the audit trail."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO audit_log (method, path, status, client_ip, request_id,
                                           user_agent, elapsed_ms, extra)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (method, path, status, client_ip, request_id, user_agent, elapsed_ms, extra))
                conn.commit()
        except Exception as e:
            logger.bind(component="database").error("Audit log write failed", error=str(e))

    def get_audit_log(self, limit: int = 100, offset: int = 0,
                      method: str = None, path_like: str = None,
                      status_min: int = None) -> List[Dict]:
        """Query the audit log with filters."""
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()

            where_clauses = []
            params = []
            if method:
                where_clauses.append("method = ?")
                params.append(method)
            if path_like:
                where_clauses.append("path LIKE ?")
                params.append(f"%{path_like}%")
            if status_min:
                where_clauses.append("status >= ?")
                params.append(status_min)

            where = ""
            if where_clauses:
                where = "WHERE " + " AND ".join(where_clauses)

            cursor.execute(f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                           (*params, limit, offset))
            rows = cursor.fetchall()
        return [dict(r) for r in rows]

    # ─── Data Retention ───────────────────────────────────────────────────

    def prune_health_metrics(self, retention_days: int = 90):
        """Remove health metrics older than retention_days."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM health_metrics WHERE timestamp < datetime('now', ?)",
                (f"-{retention_days} days",),
            )
            deleted = cursor.rowcount
            conn.commit()
        if deleted:
            logger.bind(component="database").info(
                "Pruned health metrics", count=deleted, retention_days=retention_days
            )
        return deleted

    def prune_audit_log(self, retention_days: int = 30):
        """Remove audit log entries older than retention_days."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM audit_log WHERE timestamp < datetime('now', ?)",
                (f"-{retention_days} days",),
            )
            deleted = cursor.rowcount
            conn.commit()
        if deleted:
            logger.bind(component="database").info(
                "Pruned audit log", count=deleted, retention_days=retention_days
            )
        return deleted

    def prune_old_captures(self, retention_days: int = 7, captures_dir: str = "captures"):
        """Remove capture files older than retention_days."""
        deleted = 0
        now_ts = time.time()
        cutoff = now_ts - (retention_days * 86400)
        if os.path.isdir(captures_dir):
            for fname in os.listdir(captures_dir):
                fpath = os.path.join(captures_dir, fname)
                if fname.endswith(".pcap") and os.path.isfile(fpath):
                    if os.path.getmtime(fpath) < cutoff:
                        try:
                            os.remove(fpath)
                            deleted += 1
                        except Exception:
                            pass
        if deleted:
            logger.bind(component="database").info(
                "Pruned old captures", count=deleted, retention_days=retention_days
            )
        return deleted

    # ─── Scans ────────────────────────────────────────────────────────────

    def start_scan(self, target: Optional[str], profile: str, duration: Optional[int],
                    trace_hops: bool, requester: str = "system", origin: str = "manual",
                    schedule_id: Optional[int] = None) -> int:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scans (target, profile, duration, trace_hops, status, origin)
                VALUES (?, ?, ?, ?, 'running', ?)
            ''', (target, profile, duration, trace_hops, origin))
            scan_id = cursor.lastrowid
            conn.commit()
        return scan_id

    def complete_scan(self, scan_id: int, total_devices: int, subnets_scanned: int):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE scans SET completed_at = CURRENT_TIMESTAMP, status = 'completed',
                                total_devices = ?, subnets_scanned = ?
                WHERE id = ?
            ''', (total_devices, subnets_scanned, scan_id))
            conn.commit()

    def save_scan_results(self, scan_id: int, devices: List[Dict]):
        """Save device snapshots for a completed scan (used for diffing)."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            for dev in devices:
                cursor.execute('''
                    INSERT INTO scan_results (scan_id, ip, hostname, mac, vendor, os, ports_json, latency_ms, hop_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    dev.get("ip"),
                    dev.get("hostname"),
                    dev.get("mac"),
                    dev.get("vendor"),
                    dev.get("os"),
                    json.dumps(dev.get("ports", [])),
                    dev.get("latency_ms"),
                    dev.get("hop_count"),
                ))
            conn.commit()
        logger.bind(component="database").info(
            "Saved scan results", scan_id=scan_id, devices=len(devices)
        )

    def get_previous_scan(self, target: str, current_scan_id: int) -> Optional[int]:
        """Get the most recent completed scan ID for a target before the current one."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM scans WHERE target = ? AND status = 'completed' AND id < ? ORDER BY id DESC LIMIT 1",
                (target, current_scan_id),
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def get_scan_results_by_scan(self, scan_id: int) -> List[Dict]:
        """Get device results for a specific scan."""
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,))
            rows = [dict(r) for r in cursor.fetchall()]
        return rows

    def get_scan_diff(self, scan_id: int) -> Optional[dict]:
        """Compare scan results with the previous completed scan on same target.

        Returns a diff dict with new/missing/changed devices.
        """
        # Get the current scan's target + previous scan ID
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT target FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            target = row[0]

            cursor.execute(
                "SELECT id FROM scans WHERE target = ? AND status = 'completed' AND id < ? ORDER BY id DESC LIMIT 1",
                (target, scan_id),
            )
            prev = cursor.fetchone()
            if not prev:
                return None
            prev_scan_id = prev[0]

        # Get results for both scans (separate connection for fresh row_factory)
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ip, ports_json FROM scan_results WHERE scan_id = ?", (prev_scan_id,))
            prev_rows = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT ip, ports_json FROM scan_results WHERE scan_id = ?", (scan_id,))
            curr_rows = [dict(r) for r in cursor.fetchall()]

        # Build sets
        prev_data: Dict[str, set] = {}
        curr_data: Dict[str, set] = {}
        prev_ip_set = set()
        curr_ip_set = set()

        for r in prev_rows:
            ports = json.loads(r["ports_json"]) if r.get("ports_json") else []
            prev_data[r["ip"]] = set(p["port"] for p in ports if p.get("state") == "open")
            prev_ip_set.add(r["ip"])

        for r in curr_rows:
            ports = json.loads(r["ports_json"]) if r.get("ports_json") else []
            curr_data[r["ip"]] = set(p["port"] for p in ports if p.get("state") == "open")
            curr_ip_set.add(r["ip"])

        diff = {
            "scan_id": scan_id,
            "previous_scan_id": prev_scan_id,
            "new_devices": [{"ip": ip} for ip in curr_ip_set - prev_ip_set],
            "missing_devices": [{"ip": ip} for ip in prev_ip_set - curr_ip_set],
            "changed_ports": [],
        }

        for ip in curr_ip_set & prev_ip_set:
            old_ports = prev_data.get(ip, set())
            new_ports = curr_data.get(ip, set())
            added = new_ports - old_ports
            removed = old_ports - new_ports
            if added or removed:
                diff["changed_ports"].append({
                    "ip": ip,
                    "added": list(added),
                    "removed": list(removed),
                })

        if not any([diff["new_devices"], diff["missing_devices"], diff["changed_ports"]]):
            return None

        return diff

    def get_latest_scan(self) -> Optional[Dict]:
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 1')
            row = cursor.fetchone()
        return dict(row) if row else None

    def get_scan_status(self) -> Optional[Dict]:
        """Get latest scan status."""
        return self.get_latest_scan()

    def get_scan_history(self, limit: int = 20, offset: int = 0) -> List[Dict]:
        """Get scan history with pagination."""
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            rows = [dict(r) for r in cursor.fetchall()]
        return rows

    # ─── Devices ──────────────────────────────────────────────────────────

    def upsert_device(self, scan_id: int, device_data: Dict) -> int:
        """Insert or update device. Returns device_id."""
        with self._get_conn() as conn:
            cursor = conn.cursor()

            # Upsert device
            cursor.execute('''
                INSERT INTO devices (scan_id, ip, mac, vendor, hostname, os, latency_ms,
                                     distance, hop_count, strength, vulns_detected, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(ip) DO UPDATE SET
                    scan_id = excluded.scan_id,
                    mac = excluded.mac,
                    vendor = excluded.vendor,
                    hostname = excluded.hostname,
                    os = excluded.os,
                    latency_ms = excluded.latency_ms,
                    distance = excluded.distance,
                    hop_count = excluded.hop_count,
                    strength = excluded.strength,
                    vulns_detected = excluded.vulns_detected,
                    last_seen = CURRENT_TIMESTAMP
            ''', (
                scan_id,
                device_data['ip'],
                device_data.get('mac'),
                device_data.get('vendor'),
                device_data.get('hostname'),
                device_data.get('os'),
                device_data.get('latency_ms'),
                device_data.get('distance'),
                device_data.get('hop_count'),
                device_data.get('strength', 0),
                device_data.get('vulns_detected', False)
            ))

            # Get device_id
            cursor.execute('SELECT id FROM devices WHERE ip = ?', (device_data['ip'],))
            device_id = cursor.fetchone()[0]

            # Upsert ports
            for port in device_data.get('ports', []):
                cursor.execute('''
                    INSERT OR REPLACE INTO ports (device_id, port, protocol, state, service, version, product)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_id,
                    port['port'],
                    port['protocol'],
                    port.get('state'),
                    port.get('service'),
                    port.get('version'),
                    port.get('product')
                ))

            conn.commit()
        return device_id

    def get_all_devices(self) -> List[Dict]:
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT d.*, GROUP_CONCAT(json_object(
                    'port', p.port, 'protocol', p.protocol,
                    'state', p.state, 'service', p.service,
                    'version', p.version, 'product', p.product
                )) as ports_json
                FROM devices d
                LEFT JOIN ports p ON d.id = p.device_id
                GROUP BY d.id
                ORDER BY d.ip
            ''')
            rows = cursor.fetchall()

        devices = []
        for row in rows:
            device = dict(row)
            if device['ports_json']:
                device['ports'] = json.loads(f"[{device['ports_json']}]")
            else:
                device['ports'] = []
            devices.append(device)
        return devices

    def get_device(self, device_id: int) -> Optional[Dict]:
        """Get a single device by ID with its ports."""
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT d.*, GROUP_CONCAT(json_object(
                    'port', p.port, 'protocol', p.protocol,
                    'state', p.state, 'service', p.service,
                    'version', p.version, 'product', p.product
                )) as ports_json
                FROM devices d
                LEFT JOIN ports p ON d.id = p.device_id
                WHERE d.id = ?
                GROUP BY d.id
            ''', (device_id,))
            row = cursor.fetchone()
        if not row:
            return None
        device = dict(row)
        if device['ports_json']:
            device['ports'] = json.loads(f"[{device['ports_json']}]")
        else:
            device['ports'] = []
        return device

    def get_device_by_ip(self, ip: str) -> Optional[Dict]:
        """Get a single device by IP with its ports."""
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM devices WHERE ip = ?', (ip,))
            row = cursor.fetchone()
        if not row:
            return None
        return self.get_device(row[0])

    def delete_device(self, device_id: int) -> bool:
        """Delete a device and its related data."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ports WHERE device_id = ?", (device_id,))
            cursor.execute("DELETE FROM health_metrics WHERE device_id = ?", (device_id,))
            cursor.execute("DELETE FROM vulnerabilities WHERE device_id = ?", (device_id,))
            cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            conn.commit()
        return cursor.rowcount > 0

    # ─── Health Metrics ───────────────────────────────────────────────────

    def record_health(self, device_id: int, latency_ms: float, status: str = 'up', packet_loss: bool = False):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO health_metrics (device_id, latency_ms, status, packet_loss)
                VALUES (?, ?, ?, ?)
            ''', (device_id, latency_ms, status, packet_loss))
            conn.commit()

    def get_health_history(self, device_id: int, hours: int = 24) -> List[Dict]:
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()
            cutoff = datetime.datetime.now() - datetime.timedelta(hours=hours)
            cursor.execute('''
                SELECT * FROM health_metrics
                WHERE device_id = ? AND timestamp > ?
                ORDER BY timestamp DESC
            ''', (device_id, cutoff))
            rows = cursor.fetchall()
        return [dict(r) for r in rows]

    # ─── Geolocation ──────────────────────────────────────────────────────

    def cache_geolocation(self, ip: str, geo_data: Dict):
        """Cache geolocation info for an IP."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO geolocation
                (ip, country, region, city, asn, org, latitude, longitude, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                ip,
                geo_data.get('country'),
                geo_data.get('region'),
                geo_data.get('city'),
                geo_data.get('asn'),
                geo_data.get('org'),
                geo_data.get('latitude'),
                geo_data.get('longitude')
            ))
            conn.commit()

    def get_geolocation(self, ip: str) -> Optional[Dict]:
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM geolocation WHERE ip = ?', (ip,))
            row = cursor.fetchone()
        return dict(row) if row else None

    # ─── Vulnerabilities ──────────────────────────────────────────────────

    def add_vulnerability(self, device_id: Optional[int] = None, port_id: Optional[int] = None,
                          vuln_data: Dict = None, device_ip: Optional[str] = None) -> Optional[int]:
        """Add a vulnerability record. If device_ip provided, resolves device_id."""
        if vuln_data is None:
            vuln_data = {}

        # Resolve device_id from IP if needed
        if device_id is None and device_ip:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM devices WHERE ip = ?", (device_ip,))
                row = cursor.fetchone()
                if row:
                    device_id = row[0]

        if device_id is None:
            logger.bind(component="database").warning(
                "Cannot add vulnerability — no device_id or IP",
                device_ip=device_ip,
            )
            return None

        vuln_id = None
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO vulnerabilities (device_id, port_id, cve_id, cvss_score, severity, description, reference_urls)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_id,
                port_id,
                vuln_data.get('cve_id'),
                vuln_data.get('cvss_score'),
                vuln_data.get('severity'),
                vuln_data.get('description'),
                json.dumps(vuln_data.get('references', []))
            ))
            vuln_id = cursor.lastrowid
            conn.commit()
        return vuln_id

    def get_vulnerabilities(self, device_id: int = None) -> List[Dict]:
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()
            if device_id:
                cursor.execute('SELECT * FROM vulnerabilities WHERE device_id = ?', (device_id,))
            else:
                cursor.execute('SELECT * FROM vulnerabilities')
            rows = cursor.fetchall()
        return [dict(r) for r in rows]

    # ─── Reports ──────────────────────────────────────────────────────────

    def save_report(self, report_type: str, filename: str, scan_id: int = None) -> int:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO reports (report_type, filename, scan_id)
                VALUES (?, ?, ?)
            ''', (report_type, filename, scan_id))
            report_id = cursor.lastrowid
            conn.commit()
        return report_id

    def list_reports(self) -> List[Dict]:
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM reports ORDER BY generated_at DESC')
            rows = cursor.fetchall()
        return [dict(r) for r in rows]

    # ─── Network Correlation ──────────────────────────────────────────────

    def get_network_summary(self) -> Dict:
        """Aggregate network stats: device count by vendor, OS, open ports."""
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) as total FROM devices')
            total_devices = cursor.fetchone()[0]

            cursor.execute('''
                SELECT vendor, COUNT(*) as count
                FROM devices WHERE vendor IS NOT NULL
                GROUP BY vendor ORDER BY count DESC
            ''')
            by_vendor = [dict(r) for r in cursor.fetchall()]

            cursor.execute('''
                SELECT os, COUNT(*) as count
                FROM devices WHERE os IS NOT NULL AND os != 'Unknown'
                GROUP BY os ORDER BY count DESC
            ''')
            by_os = [dict(r) for r in cursor.fetchall()]

            cursor.execute('''
                SELECT state, COUNT(*) as count
                FROM ports GROUP BY state
            ''')
            ports_by_state = [dict(r) for r in cursor.fetchall()]

            cursor.execute('SELECT COUNT(*) as total FROM vulnerabilities')
            total_vulns = cursor.fetchone()[0]

        return {
            'total_devices': total_devices,
            'by_vendor': by_vendor,
            'by_os': by_os,
            'ports_by_state': ports_by_state,
            'total_vulnerabilities': total_vulns
        }

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 4: PACKET CAPTURE & PROTOCOL DECODING METHODS
    # ══════════════════════════════════════════════════════════════════════

    def record_traffic_snapshot(self, snapshot):
        """Record a per-second traffic snapshot for an IP."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO traffic_snapshots
                        (ip, mac, bytes_sent, bytes_recv, packets_sent, packets_recv,
                         protocols, syn_rate, port_scan_score, alert_flags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    snapshot.ip, snapshot.mac,
                    snapshot.bytes_sent, snapshot.bytes_recv,
                    snapshot.packets_sent, snapshot.packets_recv,
                    json.dumps(snapshot.protocols),
                    snapshot.syn_rate, snapshot.port_scan_score,
                    json.dumps(snapshot.alert_flags),
                ))
                conn.commit()
        except Exception as e:
            logger.bind(component="database").debug(
                "Traffic snapshot error", error=str(e))

    def record_http_log(self, data):
        """Record an HTTP request or response."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                if hasattr(data, 'method'):
                    cursor.execute("""
                        INSERT INTO http_logs (timestamp, src_ip, dst_ip, method, uri, host, log_type)
                        VALUES (?, ?, ?, ?, ?, ?, 'request')
                    """, (data.timestamp, data.src_ip, data.dst_ip, data.method, data.uri, data.host))
                else:
                    cursor.execute("""
                        INSERT INTO http_logs (timestamp, src_ip, dst_ip, status_code, log_type)
                        VALUES (?, ?, ?, ?, 'response')
                    """, (data.timestamp, data.src_ip, data.dst_ip, data.status_code))
                conn.commit()
        except Exception as e:
            logger.bind(component="database").debug("HTTP log error", error=str(e))

    def record_dns_log(self, query):
        """Record a DNS query."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO dns_logs (timestamp, src_ip, dst_ip, query_name, query_type, is_response)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (query.timestamp, query.src_ip, query.dst_ip,
                      query.query_name, query.query_type, 1 if query.is_response else 0))
                conn.commit()
        except Exception as e:
            logger.bind(component="database").debug("DNS log error", error=str(e))

    def record_tls_log(self, hs):
        """Record a TLS handshake."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO tls_logs (timestamp, src_ip, dst_ip, cipher_suite, sni, version)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (hs.timestamp, hs.src_ip, hs.dst_ip, hs.cipher_suite, hs.sni, hs.version))
                conn.commit()
        except Exception as e:
            logger.bind(component="database").debug("TLS log error", error=str(e))

    def record_dhcp_log(self, msg):
        """Record a DHCP message."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO dhcp_logs (timestamp, src_mac, hostname, vendor_class)
                    VALUES (?, ?, ?, ?)
                """, (msg.timestamp, msg.src_mac, msg.hostname, msg.vendor_class))
                conn.commit()
        except Exception as e:
            logger.bind(component="database").debug("DHCP log error", error=str(e))

    def store_suspicious_dns(self, data: dict):
        """Store a suspicious DNS tunneling alert."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO suspicious_dns (ip, timestamp, dns_server, sample_names, avg_entropy, total_queries)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    data.get("ip", ""),
                    data.get("timestamp", 0.0),
                    data.get("dns_server", ""),
                    json.dumps(data.get("sample_names", [])),
                    data.get("avg_entropy", 0.0),
                    data.get("total_queries", 0),
                ))
                conn.commit()
        except Exception as e:
            logger.bind(component="database").debug("Suspicious DNS error", error=str(e))

    def save_baseline(self, baseline):
        """Persist a device traffic baseline."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO traffic_baselines
                        (mac, ip, first_seen, last_seen, mean_bytes_per_sec, std_bytes_per_sec,
                         mean_packets_per_sec, std_packets_per_sec, protocol_profile,
                         active_hours, peer_ips, sample_count, last_anomaly_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    baseline.mac, baseline.ip, baseline.first_seen, baseline.last_seen,
                    baseline.mean_bytes_per_sec, baseline.std_bytes_per_sec,
                    baseline.mean_packets_per_sec, baseline.std_packets_per_sec,
                    json.dumps(baseline.protocol_profile),
                    json.dumps(baseline.active_hours),
                    json.dumps(list(baseline.peer_ips)),
                    baseline.sample_count, baseline.last_anomaly_score,
                ))
                conn.commit()
        except Exception as e:
            logger.bind(component="database").debug("Save baseline error", error=str(e))

    def record_anomaly(self, event):
        """Record a traffic anomaly event."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO anomaly_events (timestamp, mac, ip, score, reason, detail)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    event.timestamp, event.mac, event.ip, event.score,
                    event.reason, json.dumps(event.detail),
                ))
                conn.commit()
        except Exception as e:
            logger.bind(component="database").debug("Anomaly log error", error=str(e))

    def record_rogue_ap(self, event_type="", bssid="", ssid="",
                         src_mac="", channel=0, rssi=0, detail=""):
        """Record a rogue AP or deauth detection event."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO rogue_ap_events (event_type, bssid, ssid, src_mac, channel, rssi, detail)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (event_type, bssid, ssid, src_mac, channel, rssi, detail))
                conn.commit()
        except Exception as e:
            logger.bind(component="database").debug("Rogue AP error", error=str(e))

    def get_packet_analysis_summary(self) -> dict:
        """Get summary statistics from packet capture tables."""
        try:
            with self._get_conn(row_factory=True) as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) as c FROM traffic_snapshots")
                snapshots = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) as c FROM http_logs")
                http_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) as c FROM dns_logs")
                dns_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) as c FROM tls_logs")
                tls_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) as c FROM suspicious_dns")
                dns_suspicious = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) as c FROM anomaly_events")
                anomalies = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT ip, SUM(packets_sent + packets_recv) as total_packets,
                           SUM(bytes_sent + bytes_recv) as total_bytes
                    FROM traffic_snapshots
                    GROUP BY ip ORDER BY total_packets DESC LIMIT 10
                """)
                top_talkers = [dict(r) for r in cursor.fetchall()]

            return {
                "total_snapshots": snapshots,
                "http_requests": http_count,
                "dns_queries": dns_count,
                "tls_handshakes": tls_count,
                "dns_suspicious": dns_suspicious,
                "anomalies": anomalies,
                "top_talkers": top_talkers,
            }
        except Exception as e:
            logger.bind(component="database").debug(
                "Packet analysis summary error", error=str(e))
            return {}

    # ─── Scan Schedule Management ─────────────────────────────────────────

    def get_schedules(self) -> List[Dict]:
        """Get all scan schedules."""
        with self._get_conn(row_factory=True) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_schedules ORDER BY id")
            rows = [dict(r) for r in cursor.fetchall()]
        return rows

    def add_schedule(self, target: str, profile: str = "deep",
                     interval_minutes: int = 60, requester: str = "system") -> int:
        """Create a new scan schedule."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_schedules (target, profile, interval_minutes, requester)
                VALUES (?, ?, ?, ?)
            """, (target, profile, interval_minutes, requester))
            schedule_id = cursor.lastrowid
            conn.commit()
        return schedule_id

    def toggle_schedule(self, schedule_id: int) -> Optional[bool]:
        """Toggle a schedule's enabled status. Returns new state or None if not found."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT enabled FROM scan_schedules WHERE id = ?", (schedule_id,))
            row = cursor.fetchone()
            if not row:
                return None
            new_state = 0 if row[0] else 1
            cursor.execute("UPDATE scan_schedules SET enabled = ? WHERE id = ?", (new_state, schedule_id))
            conn.commit()
        return bool(new_state)

    def delete_schedule(self, schedule_id: int) -> bool:
        """Delete a schedule. Returns True if deleted."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scan_schedules WHERE id = ?", (schedule_id,))
            conn.commit()
        return bool(cursor.rowcount)
