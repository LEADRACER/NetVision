import sqlite3
import json
import datetime
from typing import Optional, List, Dict, Any

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

        conn.commit()
        conn.close()

    # ─── Scans ────────────────────────────────────────────────────────────────

    def start_scan(self, target: str, profile: str, duration: Optional[int], trace_hops: bool) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scans (target, profile, duration, trace_hops, status)
            VALUES (?, ?, ?, ?, 'running')
        ''', (target, profile, duration, trace_hops))
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

    def add_vulnerability(self, device_id: int, port_id: int, vuln_data: Dict):
        conn = sqlite3.connect(self.db_path)
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
