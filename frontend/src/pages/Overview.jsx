import { useState, useEffect } from 'react';
import { useWS } from '../hooks/useWS';
import { api } from '../lib/api';
import { Wifi, Activity, Shield, Radio, TrendingUp, AlertTriangle, Clock, ChevronRight } from 'lucide-react';

const statCards = [
  { key: 'devices', label: 'Devices', icon: Wifi, color: 'var(--color-accent)' },
  { key: 'scanning', label: 'Scanning', icon: Activity, color: 'var(--color-info)' },
  { key: 'vulns', label: 'Vulnerabilities', icon: Shield, color: 'var(--color-danger)' },
  { key: 'capturing', label: 'Capturing', icon: Radio, color: 'var(--color-warning)' },
  { key: 'queueDepth', label: 'Queue Depth', icon: TrendingUp, color: 'var(--color-text-dim)' },
];

export default function Overview() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [recentScans, setRecentScans] = useState([]);
  const ws = useWS();

  // Fetch on mount
  useEffect(() => {
    Promise.all([
      api.health.scan(),
      api.scan.queue(),
      api.scan.history(5),
    ]).then(([health, queue, history]) => {
      setStats({
        devices: health.devices_found || 0,
        scanning: health.is_scanning ? 1 : 0,
        vulns: health.vulnerabilities_count || 0,
        capturing: health.is_capturing ? 1 : 0,
        queueDepth: queue.queue?.length || queue.pending_count || 0,
      });
      setRecentScans(history.scans || history || []);
    }).catch(() => {});

    // Fetch vulnerabilities count
    api.vulnerabilities.list().then(v => {
      setStats(prev => prev ? { ...prev, vulns: v.vulnerabilities?.length || v.count || 0 } : prev);
    }).catch(() => {});
  }, []);

  // Listen for WS events
  useEffect(() => {
    if (!ws.lastEvent) return;
    const ev = ws.lastEvent;
    if (ev.type === 'scan.progress') {
      setStats(prev => prev ? { ...prev, scanning: ev.scanning ? 1 : 0 } : prev);
    }
    if (ev.type === 'health.alert') {
      setAlerts(prev => [ev, ...prev].slice(0, 20));
    }
    if (ev.type === 'vuln.found') {
      setStats(prev => prev ? { ...prev, vulns: (prev.vulns || 0) + 1 } : prev);
    }
  }, [ws.lastEvent]);

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 600, color: 'var(--color-text)', margin: 0 }}>
          Network Overview
        </h1>
        <p style={{ fontSize: 13.5, color: 'var(--color-text-muted)', margin: '4px 0 0' }}>
          Real-time status & activity
        </p>
      </div>

      {/* Stats Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(170px, 1fr))', gap: 12 }}>
        {statCards.map(card => {
          const val = stats ? stats[card.key] : '...';
          const isActive = card.key === 'scanning' ? val === 1 : false;
          const isDanger = card.key === 'vulns' && val > 0;
          return (
            <div key={card.key}
              style={{
                background: 'var(--color-surface)',
                borderRadius: 12,
                border: '1px solid var(--color-border)',
                padding: '16px',
                display: 'flex', flexDirection: 'column', gap: 8,
                boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
              }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{
                  width: 32, height: 32, borderRadius: 8,
                  background: isDanger ? 'var(--color-danger-bg)' : isActive ? 'var(--color-info-bg)' : 'var(--color-surface-2)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <card.icon size={15} color={card.color} strokeWidth={1.8} />
                </div>
                <span style={{ fontSize: 12, color: 'var(--color-text-muted)', fontWeight: 500 }}>{card.label}</span>
              </div>
              <span style={{
                fontSize: 26, fontWeight: 600, color: 'var(--color-text)',
                letterSpacing: '-0.02em',
              }}>
                {isActive ? (
                  <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{
                      width: 8, height: 8, borderRadius: '50%',
                      background: 'var(--color-info)',
                      animation: 'pulse-glow 1.5s infinite',
                    }} />
                    Active
                  </span>
                ) : (
                  val
                )}
              </span>
            </div>
          );
        })}
      </div>

      {/* Two-column layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, alignItems: 'start' }}>
        {/* Recent Scans */}
        <div style={{
          background: 'var(--color-surface)',
          borderRadius: 12,
          border: '1px solid var(--color-border)',
          boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
          overflow: 'hidden',
        }}>
          <div style={{
            padding: '14px 16px', borderBottom: '1px solid var(--color-border)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Activity size={15} color="var(--color-text-dim)" strokeWidth={1.8} />
              <span style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--color-text)' }}>Recent Scans</span>
            </div>
            <button onClick={() => {}} style={{
              background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-text-dim)', fontSize: 12,
              display: 'flex', alignItems: 'center', gap: 4,
            }}>
              All <ChevronRight size={12} />
            </button>
          </div>
          <div style={{ padding: 8 }}>
            {recentScans.length === 0 ? (
              <div style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--color-text-dim)', fontSize: 13 }}>
                No scans yet. Tap the + button to start one.
              </div>
            ) : recentScans.map((s, i) => (
              <div key={s.scan_id || i} style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '10px 12px', borderRadius: 8,
                fontSize: 13, color: 'var(--color-text)',
              }}>
                <div style={{
                  width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                  background: s.status === 'completed' ? 'var(--color-accent)' : s.status === 'running' ? 'var(--color-info)' : 'var(--color-text-dim)',
                }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {s.target || s.profile || 'Scan'}
                  </div>
                  <div style={{ fontSize: 11.5, color: 'var(--color-text-dim)', marginTop: 1 }}>
                    {s.profile || '—'} · {s.devices_found || 0} devices found
                  </div>
                </div>
                <Clock size={12} color="var(--color-text-dim)" />
                <span style={{ fontSize: 11.5, color: 'var(--color-text-dim)' }}>
                  {s.duration ? `${s.duration}s` : ''}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Live Event Feed */}
        <div style={{
          background: 'var(--color-surface)',
          borderRadius: 12,
          border: '1px solid var(--color-border)',
          boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
          overflow: 'hidden',
        }}>
          <div style={{
            padding: '14px 16px', borderBottom: '1px solid var(--color-border)',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <Radio size={15} color="var(--color-text-dim)" strokeWidth={1.8} />
            <span style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--color-text)' }}>Live Events</span>
            {ws.connected && (
              <span style={{
                width: 6, height: 6, borderRadius: '50%',
                background: 'var(--color-accent)',
                boxShadow: '0 0 4px var(--color-accent-glow)',
                marginLeft: 'auto',
              }} />
            )}
          </div>
          <div style={{ padding: 8, maxHeight: 320, overflow: 'auto' }}>
            {alerts.length === 0 ? (
              <div style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--color-text-dim)', fontSize: 13 }}>
                No events yet. Run a scan or wait for device alerts.
              </div>
            ) : alerts.map((ev, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'flex-start', gap: 8,
                padding: '8px 12px', borderRadius: 6,
                fontSize: 12.5, color: 'var(--color-text)',
                animation: i === 0 ? 'fade-in 0.3s ease-out' : 'none',
              }}>
                <AlertTriangle size={12} color={ev.level === 'critical' ? 'var(--color-danger)' : 'var(--color-warning)'}
                  style={{ flexShrink: 0, marginTop: 2 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 500 }}>{ev.message || ev.type}</div>
                  <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 1 }}>
                    {ev.device_ip || ''} · {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'now'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
