import sqlite3
import json
import datetime
from typing import Optional, List, Dict, Any
from loguru import logger

class Database:
    def __init__(self, db_path="netvision.db"):
        self.db_path = db_path
        self.init_tables()

    def init_tables(self):
        """Create all necessary tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
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
        
        # Add origin column to scans if missing
        cursor.execute("PRAGMA table_info(scans)")
        columns = [r[1] for r in cursor.fetchall()]
        if "origin" not in columns:
            cursor.execute("ALTER TABLE scans ADD COLUMN origin TEXT DEFAULT 'manual'")

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

        # Enable WAL mode for better concurrent performance
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass

        conn.commit()
        conn.close()

    # ─── Audit Log ────────────────────────────────────────────────────────────

    def record_audit(self, method: str, path: str, status: int,
                     client_ip: str = "", request_id: str = "",
                     user_agent: str = "", elapsed_ms: float = 0,
                     extra: str = ""):
        """Record an API access to the audit trail."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_log (method, path, status, client_ip, request_id,
                                       user_agent, elapsed_ms, extra)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (method, path, status, client_ip, request_id, user_agent, elapsed_ms, extra))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.bind(component="database").error("Audit log write failed", error=str(e))

    def get_audit_log(self, limit: int = 100, offset: int = 0,
                      method: str = None, path_like: str = None,
                      status_min: int = None) -> List[Dict]:
        """Query the audit log with filters."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
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
        conn.close()
        return [dict(r) for r in rows]

    # ─── Data Retention ───────────────────────────────────────────────────────

    def prune_health_metrics(self, retention_days: int = 90):
        """Remove health metrics older than retention_days."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM health_metrics WHERE timestamp < datetime('now', ?)",
            (f"-{retention_days} days",),
        )
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        if deleted:
            logger.bind(component="database").info(
                "Pruned health metrics", count=deleted, retention_days=retention_days
            )
        return deleted

    def prune_audit_log(self, retention_days: int = 30):
        """Remove audit log entries older than retention_days."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM audit_log WHERE timestamp < datetime('now', ?)",
            (f"-{retention_days} days",),
        )
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        if deleted:
            logger.bind(component="database").info(
                "Pruned audit log", count=deleted, retention_days=retention_days
            )
        return deleted

    def prune_old_captures(self, retention_days: int = 7, captures_dir: str = "captures"):
        """Remove capture files older than retention_days."""
        import os, time
        deleted = 0
        now = time.time()
        cutoff = now - (retention_days * 86400)
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

    # ─── Scans ────────────────────────────────────────────────────────────────

    def start_scan(self, target: Optional[str], profile: str, duration: Optional[int],
                    trace_hops: bool, requester: str = "system", origin: str = "manual",
                    schedule_id: Optional[int] = None) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scans (target, profile, duration, trace_hops, status, origin)
            VALUES (?, ?, ?, ?, 'running', ?)
        ''', (target, profile, duration, trace_hops, origin))
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def complete_scan(self, scan_id: int, total_devices: int, subnets_scanned: int):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE scans SET completed_at = CURRENT_TIMESTAMP, status = 'completed',
                            total_devices = ?, subnets_scanned = ?
            WHERE id = ?
        ''', (total_devices, subnets_scanned, scan_id))
        conn.commit()
        conn.close()

    def save_scan_results(self, scan_id: int, devices: List[Dict]):
        """Save device snapshots for a completed scan (used for diffing)."""
        conn = sqlite3.connect(self.db_path)
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
        conn.close()
        logger.bind(component="database").info(
            "Saved scan results", scan_id=scan_id, devices=len(devices)
        )

    def get_previous_scan(self, target: str, current_scan_id: int) -> Optional[int]:
        """Get the most recent completed scan ID for a target before the current one."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM scans WHERE target = ? AND status = 'completed' AND id < ? ORDER BY id DESC LIMIT 1",
            (target, current_scan_id),
        )
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def get_scan_results_by_scan(self, scan_id: int) -> List[Dict]:
        """Get device results for a specific scan."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def get_scan_diff(self, scan_id: int) -> Optional[dict]:
        """Compare scan results with the previous completed scan on same target.
        Returns a diff dict with new/missing/changed devices."""
        # Get the current scan's target
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT target FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None
        target = row[0]

        # Find previous scan on same target
        cursor.execute(
            "SELECT id FROM scans WHERE target = ? AND status = 'completed' AND id < ? ORDER BY id DESC LIMIT 1",
            (target, scan_id),
        )
        prev = cursor.fetchone()
        if not prev:
            conn.close()
            return None
        prev_scan_id = prev[0]
        conn.close()

        # Get results for both scans
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT ip, ports_json FROM scan_results WHERE scan_id = ?", (prev_scan_id,))
        prev_rows = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT ip, ports_json FROM scan_results WHERE scan_id = ?", (scan_id,))
        curr_rows = [dict(r) for r in cursor.fetchall()]

        conn.close()

        # Build sets
        prev: Dict[str, set] = {}
        curr: Dict[str, set] = {}
        prev_ip_set = set()
        curr_ip_set = set()

        for r in prev_rows:
            ports = json.loads(r["ports_json"]) if r.get("ports_json") else []
            prev[r["ip"]] = set(p["port"] for p in ports if p.get("state") == "open")
            prev_ip_set.add(r["ip"])

        for r in curr_rows:
            ports = json.loads(r["ports_json"]) if r.get("ports_json") else []
            curr[r["ip"]] = set(p["port"] for p in ports if p.get("state") == "open")
            curr_ip_set.add(r["ip"])

        diff = {
            "scan_id": scan_id,
            "previous_scan_id": prev_scan_id,
            "new_devices": [{"ip": ip} for ip in curr_ip_set - prev_ip_set],
            "missing_devices": [{"ip": ip} for ip in prev_ip_set - curr_ip_set],
            "changed_ports": [],
        }

        for ip in curr_ip_set & prev_ip_set:
            old_ports = prev.get(ip, set())
            new_ports = curr.get(ip, set())
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
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 1')
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    # ─── Devices ──────────────────────────────────────────────────────────────

    def upsert_device(self, scan_id: int, device_data: Dict) -> int:
        """Insert or update device. Returns device_id."""
        conn = sqlite3.connect(self.db_path)
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
        conn.close()
        return device_id

    def get_all_devices(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
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
        conn.close()

        devices = []
        for row in rows:
            device = dict(row)
            if device['ports_json']:
                device['ports'] = json.loads(f"[{device['ports_json']}]")
            else:
                device['ports'] = []
            devices.append(device)
        return devices

    # ─── Health Metrics ───────────────────────────────────────────────────────

    def record_health(self, device_id: int, latency_ms: float, status: str = 'up', packet_loss: bool = False):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO health_metrics (device_id, latency_ms, status, packet_loss)
            VALUES (?, ?, ?, ?)
        ''', (device_id, latency_ms, status, packet_loss))
        conn.commit()
        conn.close()

    def get_health_history(self, device_id: int, hours: int = 24) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=hours)
        cursor.execute('''
            SELECT * FROM health_metrics
            WHERE device_id = ? AND timestamp > ?
            ORDER BY timestamp DESC
        ''', (device_id, cutoff))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # ─── Geolocation ──────────────────────────────────────────────────────────

    def cache_geolocation(self, ip: str, geo_data: Dict):
        """Cache geolocation info for an IP."""
        conn = sqlite3.connect(self.db_path)
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
        conn.close()

    def get_geolocation(self, ip: str) -> Optional[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM geolocation WHERE ip = ?', (ip,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    # ─── Vulnerabilities ──────────────────────────────────────────────────────

    def add_vulnerability(self, device_id: Optional[int] = None, port_id: Optional[int] = None,
                          vuln_data: Dict = None, device_ip: Optional[str] = None) -> Optional[int]:
        """Add a vulnerability record. If device_ip provided, resolves device_id."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Resolve device_id from IP if provided
        if device_id is None and device_ip:
            cursor.execute("SELECT id FROM devices WHERE ip = ?", (device_ip,))
            row = cursor.fetchone()
            if row:
                device_id = row[0]

        if device_id is None:
            logger.bind(component="database").warning(
                "Cannot add vulnerability — no device_id or IP",
                device_ip=device_ip,
            )
            conn.close()
            return None

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
        conn.commit()
        conn.close()

    def get_vulnerabilities(self, device_id: int = None) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if device_id:
            cursor.execute('SELECT * FROM vulnerabilities WHERE device_id = ?', (device_id,))
        else:
            cursor.execute('SELECT * FROM vulnerabilities')
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # ─── Reports ──────────────────────────────────────────────────────────────

    def save_report(self, report_type: str, filename: str, scan_id: int = None) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO reports (report_type, filename, scan_id)
            VALUES (?, ?, ?)
        ''', (report_type, filename, scan_id))
        report_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return report_id

    def list_reports(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM reports ORDER BY generated_at DESC')
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # ─── Network Correlation ──────────────────────────────────────────────────

    def get_network_summary(self) -> Dict:
        """Aggregate network stats: device count by vendor, OS, open ports."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
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

        conn.close()
        return {
            'total_devices': total_devices,
            'by_vendor': by_vendor,
            'by_os': by_os,
            'ports_by_state': ports_by_state,
            'total_vulnerabilities': total_vulns
        }
