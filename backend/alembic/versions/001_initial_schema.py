"""Initial NetVision database schema.

Creates all 20 tables and their indexes.

Revision ID: 001
Revises: None
Create Date: 2026-06-25
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ═════════════════════════════════════════════════════════════════════
    # CORE TABLES
    # ═════════════════════════════════════════════════════════════════════

    op.execute("""
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
    """)
    op.execute("ALTER TABLE scans ADD COLUMN origin TEXT DEFAULT 'manual'")

    op.execute("""
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
    """)

    op.execute("""
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
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS health_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            latency_ms REAL,
            packet_loss BOOLEAN DEFAULT 0,
            status TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)

    op.execute("""
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
    """)

    op.execute("""
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
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            report_type TEXT,
            filename TEXT,
            scan_id INTEGER,
            exported_by TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    op.execute("""
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
    """)

    op.execute("""
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

    op.execute("""
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

    # ═════════════════════════════════════════════════════════════════════
    # PHASE 4: PACKET CAPTURE TABLES
    # ═════════════════════════════════════════════════════════════════════

    op.execute("""
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

    op.execute("""
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

    op.execute("""
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

    op.execute("""
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

    op.execute("""
        CREATE TABLE IF NOT EXISTS dhcp_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            src_mac TEXT DEFAULT '',
            hostname TEXT DEFAULT '',
            vendor_class TEXT DEFAULT ''
        )
    """)

    op.execute("""
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

    op.execute("""
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

    op.execute("""
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

    op.execute("""
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

    # ═════════════════════════════════════════════════════════════════════
    # INDEXES
    # ═════════════════════════════════════════════════════════════════════

    # Scan results index
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_results_scan_ip
        ON scan_results(scan_id, ip)
    """)

    # Phase 4 indexes
    for table, col in [
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
        op.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{table}_{col} ON {table}({col})"
        )

    # Core table indexes
    for table, col in [
        ("devices", "ip"),
        ("health_metrics", "timestamp"),
        ("health_metrics", "device_id"),
        ("scans", "started_at"),
        ("audit_log", "timestamp"),
        ("ports", "device_id"),
    ]:
        op.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{table}_{col} ON {table}({col})"
        )


def downgrade() -> None:
    """Drop all tables and indexes (reverse order of creation)."""
    tables = [
        "rogue_ap_events",
        "anomaly_events",
        "traffic_baselines",
        "suspicious_dns",
        "dhcp_logs",
        "tls_logs",
        "dns_logs",
        "http_logs",
        "traffic_snapshots",
        "scan_results",
        "scan_schedules",
        "audit_log",
        "reports",
        "vulnerabilities",
        "geolocation",
        "health_metrics",
        "ports",
        "devices",
        "scans",
    ]
    for table in tables:
        op.execute(f"DROP TABLE IF EXISTS {table}")
