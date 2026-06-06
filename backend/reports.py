import sqlite3
import json
import csv
import io
import os
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import html

# Optional: reportlab for PDF generation (install via pip install reportlab)
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

@dataclass
class ReportContext:
    scan_id: Optional[int]
    devices: List[Dict]
    summary: Dict
    generated_at: datetime
    report_type: str

class ReportGenerator:
    """Generate scan reports in various formats (HTML, PDF, JSON, CSV)."""
    
    def __init__(self, db):
        self.db = db
        self.reports_dir = "reports"
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate(self, scan_id: Optional[int] = None, format: str = 'html', filename: Optional[str] = None) -> str:
        """Generate a report for the given scan or latest scan."""
        if scan_id is None:
            scan = self.db.get_latest_scan()
            if not scan:
                raise ValueError("No scans available")
            scan_id = scan['id']
        
        # Gather data
        devices = self.db.get_all_devices()
        summary = self.db.get_network_summary()
        
        ctx = ReportContext(
            scan_id=scan_id,
            devices=devices,
            summary=summary,
            generated_at=datetime.now(),
            report_type=format
        )
        
        if format == 'html':
            return self._generate_html(ctx, filename)
        elif format == 'pdf':
            return self._generate_pdf(ctx, filename)
        elif format == 'json':
            return self._generate_json(ctx, filename)
        elif format == 'csv':
            return self._generate_csv(ctx, filename)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_html(self, ctx: ReportContext, filename: Optional[str]) -> str:
        """Generate an HTML report with embedded CSS."""
        devices_html = ""
        for dev in ctx.devices:
            ports_list = ', '.join([f"{p['port']}/{p['protocol']} ({p['service']})" for p in dev['ports']])
            vuln_badge = '<span class="badge badge-danger">VULNS</span>' if dev['vulns_detected'] else ''
            hop_badge = f'<span class="badge badge-info">↗ {dev["hop_count"]}</span>' if dev.get('hop_count') else ''
            
            devices_html += f"""
            <tr>
                <td>{html.escape(dev['ip'])}</td>
                <td>{html.escape(dev['mac'] or 'N/A')}</td>
                <td>{html.escape(dev['vendor'] or 'Unknown')}</td>
                <td>{html.escape(dev['os'] or 'Unknown')}</td>
                <td>{ports_list}</td>
                <td>{dev['latency_ms']:.2f} ms</td>
                <td>{hop_badge} {vuln_badge}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>NetVision Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; color: #333; }}
        h1, h2 {{ color: #18181b; }}
        .header {{ background: #3f3f46; color: #fff; padding: 2rem; margin: -40px -40px 2rem; border-radius: 0 0 10px 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1.5rem; margin-bottom: 2rem; }}
        .stat-card {{ background: #fff; padding: 1.5rem; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }}
        .stat-value {{ font-size: 2.5rem; font-weight: 700; color: #22c55e; }}
        .stat-label {{ font-size: 0.9rem; color: #71717a; text-transform: uppercase; }}
        table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #e4e4e7; }}
        th {{ background: #f4f4f5; font-weight: 700; color: #18181b; }}
        tr:hover {{ background: #fafafa; }}
        .badge {{ padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }}
        .badge-danger {{ background: #fee2e2; color: #991b1b; }}
        .badge-info {{ background: #dbeafe; color: #1e40af; }}
        .footer {{ margin-top: 2rem; font-size: 0.8rem; color: #71717a; text-align: center; }}
        @media print {{ body {{ margin: 0; }} .header {{ margin: 0 -40px 2rem; }} }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🌐 NetVision Scan Report</h1>
        <p>Generated: {ctx.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="summary">
        <div class="stat-card">
            <div class="stat-value">{ctx.summary['total_devices']}</div>
            <div class="stat-label">Total Devices</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{ctx.summary['total_vulnerabilities']}</div>
            <div class="stat-label">Vulnerabilities</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{len([d for d in ctx.devices if d.get('hop_count')])}</div>
            <div class="stat-label">With Hops</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{ctx.summary.get('ports_by_state', [{}])[0].get('open', 0)}</div>
            <div class="stat-label">Open Ports</div>
        </div>
    </div>

    <h2>Device Inventory</h2>
    <table>
        <thead>
            <tr>
                <th>IP</th>
                <th>MAC</th>
                <th>Vendor</th>
                <th>OS</th>
                <th>Ports</th>
                <th>Latency</th>
                <th>Flags</th>
            </tr>
        </thead>
        <tbody>
            {devices_html}
        </tbody>
    </table>

    <div class="footer">
        <p>Generated by NetVision v4.3.0 | {datetime.now().year}</p>
    </div>
</body>
</html>"""
        
        # Save file
        if not filename:
            filename = f"report_{ctx.scan_id}_{ctx.generated_at.strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.reports_dir, filename)
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        # Save record
        self.db.save_report('html', filename, ctx.scan_id)
        return filepath

    def _generate_json(self, ctx: ReportContext, filename: Optional[str]) -> str:
        data = {
            'scan_id': ctx.scan_id,
            'generated_at': ctx.generated_at.isoformat(),
            'summary': ctx.summary,
            'devices': [asdict(d) for d in ctx.devices]
        }
        if not filename:
            filename = f"report_{ctx.scan_id}_{ctx.generated_at.strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.reports_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        self.db.save_report('json', filename, ctx.scan_id)
        return filepath

    def _generate_csv(self, ctx: ReportContext, filename: Optional[str]) -> str:
        if not filename:
            filename = f"report_{ctx.scan_id}_{ctx.generated_at.strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'MAC', 'Vendor', 'OS', 'Latency', 'Distance', 'Hop Count', 'Vulnerable', 'Ports'])
            for dev in ctx.devices:
                ports = ';'.join([f"{p['port']}/{p['protocol']}:{p['service']}" for p in dev['ports']])
                writer.writerow([
                    dev['ip'],
                    dev.get('mac', ''),
                    dev.get('vendor', ''),
                    dev.get('os', ''),
                    dev.get('latency_ms', ''),
                    dev.get('distance', ''),
                    dev.get('hop_count', ''),
                    dev.get('vulns_detected', False),
                    ports
                ])
        self.db.save_report('csv', filename, ctx.scan_id)
        return filepath

    def _generate_pdf(self, ctx: ReportContext, filename: Optional[str]) -> str:
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab not installed. Run: pip install reportlab")
        
        if not filename:
            filename = f"report_{ctx.scan_id}_{ctx.generated_at.strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=18, spaceAfter=30)
        story.append(Paragraph("🌐 NetVision Scan Report", title_style))
        story.append(Spacer(1, 12))
        
        # Summary table
        summary_data = [
            ['Metric', 'Value'],
            ['Total Devices', ctx.summary['total_devices']],
            ['Vulnerabilities', ctx.summary['total_vulnerabilities']],
            ['With Hops', len([d for d in ctx.devices if d.get('hop_count')])],
            ['Generated', ctx.generated_at.strftime('%Y-%m-%d %H:%M:%S')]
        ]
        table = Table(summary_data, colWidths=[200, 200])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        story.append(table)
        story.append(Spacer(1, 30))
        
        # Device table
        story.append(Paragraph("Device Inventory", styles['Heading2']))
        device_data = [['IP', 'MAC', 'Vendor', 'OS', 'Open Ports', 'Latency']]
        for dev in ctx.devices[:100]:  # Limit to first 100 for PDF
            ports = ', '.join([f"{p['port']}/{p['protocol']}" for p in dev['ports'][:3]])
            if len(dev['ports']) > 3:
                ports += f' (+{len(dev["ports"])-3} more)'
            device_data.append([
                dev['ip'],
                dev.get('mac', '')[:17],
                (dev.get('vendor') or 'Unknown')[:30],
                (dev.get('os') or 'Unknown')[:30],
                ports,
                f"{dev.get('latency_ms', 0):.2f} ms"
            ])
        
        dev_table = Table(device_data, colWidths=[80, 100, 90, 90, 100, 60])
        dev_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,0), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.lightgrey])
        ]))
        story.append(dev_table)
        
        doc.build(story)
        self.db.save_report('pdf', filename, ctx.scan_id)
        return filepath
