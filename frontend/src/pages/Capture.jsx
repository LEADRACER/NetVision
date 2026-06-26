import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { useWS } from '../hooks/useWS';
import { Radio, Activity, AlertTriangle, Globe, BarChart3, Play, Square, Loader2 } from 'lucide-react';

export default function Capture() {
  const [summary, setSummary] = useState(null);
  const [talkers, setTalkers] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [capturing, setCapturing] = useState(false);
  const [duration, setDuration] = useState(60);
  const ws = useWS();

  useEffect(() => {
    api.capture.summary().then(setSummary).catch(() => {});
    api.capture.topTalkers().then(d => setTalkers(d.talkers || d || [])).catch(() => {});
    api.capture.anomalies(2).then(d => setAnomalies(d.anomalies || d || [])).catch(() => {});
    api.capture.status().then(s => setCapturing(s.is_capturing || s.active || false)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!ws.lastEvent) return;
    const ev = ws.lastEvent;
    if (ev.type === 'capture.data') {
      setCapturing(true);
    }
    if (ev.type === 'capture.state') {
      setCapturing(ev.active);
      if (!ev.active) {
        api.capture.summary().then(setSummary).catch(() => {});
      }
    }
  }, [ws.lastEvent]);

  const handleStart = () => {
    api.capture.startStreaming(duration).then(() => setCapturing(true)).catch(() => {});
  };
  const handleStop = () => {
    api.capture.stopStreaming().then(() => setCapturing(false)).catch(() => {});
  };

  const stats = [
    { label: 'Snapshots', value: summary?.traffic_snapshots || 0 },
    { label: 'HTTP Logs', value: summary?.http_logs || 0 },
    { label: 'DNS Queries', value: summary?.dns_logs || 0 },
    { label: 'Anomalies', value: summary?.anomaly_events || 0 },
    { label: 'Rogue Events', value: summary?.rogue_ap_events || 0 },
  ];

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header + controls */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 600, color: 'var(--color-text)', margin: 0 }}>
            Packet Capture
          </h1>
          <p style={{ fontSize: 13.5, color: 'var(--color-text-muted)', margin: '4px 0 0' }}>
            Live traffic analysis & protocol decoding
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {capturing ? (
            <button onClick={handleStop}
              style={{
                padding: '8px 16px', borderRadius: 8,
                background: 'var(--color-danger)', color: '#fff',
                border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 500,
                display: 'flex', alignItems: 'center', gap: 6,
              }}>
              <Square size={13} /> Stop Capture
            </button>
          ) : (
            <>
              <input type="number" value={duration} min={10} max={600}
                onChange={e => setDuration(Math.min(600, Math.max(10, parseInt(e.target.value) || 60)))}
                style={{
                  width: 70, padding: '8px 10px', borderRadius: 8,
                  border: '1px solid var(--color-border)',
                  background: 'var(--color-surface)',
                  fontSize: 13, color: 'var(--color-text)', outline: 'none',
                }} />
              <button onClick={handleStart}
                style={{
                  padding: '8px 16px', borderRadius: 8,
                  background: 'var(--color-accent)', color: '#fff',
                  border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 500,
                  display: 'flex', alignItems: 'center', gap: 6,
                }}>
                <Play size={13} /> Start {duration}s
              </button>
            </>
          )}
        </div>
      </div>

      {/* Capturing indicator */}
      {capturing && (
        <div style={{
          padding: '10px 16px', borderRadius: 10,
          background: 'var(--color-info-bg)',
          border: '1px solid var(--color-info)',
          display: 'flex', alignItems: 'center', gap: 8,
          fontSize: 13, color: 'var(--color-info)',
          animation: 'fade-in 0.3s ease-out',
        }}>
          <Loader2 size={14} className="animate-spin" />
          <span style={{ fontWeight: 500 }}>Capturing live traffic — streaming packets via tshark</span>
        </div>
      )}

      {/* Summary stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: 10 }}>
        {stats.map(s => (
          <div key={s.label} style={{
            background: 'var(--color-surface)', borderRadius: 10,
            border: '1px solid var(--color-border)',
            padding: '14px',
            boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
          }}>
            <div style={{ fontSize: 11.5, color: 'var(--color-text-muted)', fontWeight: 500 }}>{s.label}</div>
            <div style={{ fontSize: 22, fontWeight: 600, color: 'var(--color-text)', marginTop: 4 }}>{s.value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, alignItems: 'start' }}>
        {/* Top Talkers */}
        <div style={{
          background: 'var(--color-surface)', borderRadius: 12,
          border: '1px solid var(--color-border)',
          boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
          overflow: 'hidden',
        }}>
          <div style={{
            padding: '14px 16px', borderBottom: '1px solid var(--color-border)',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <BarChart3 size={15} color="var(--color-text-dim)" strokeWidth={1.8} />
            <span style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--color-text)' }}>Top Talkers</span>
          </div>
          {talkers.length === 0 ? (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--color-text-dim)', fontSize: 13 }}>
              No traffic data yet.
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--color-border)', background: 'var(--color-surface-2)' }}>
                  <th style={{ textAlign: 'left', padding: '8px 14px', fontWeight: 500, color: 'var(--color-text-dim)' }}>IP</th>
                  <th style={{ textAlign: 'right', padding: '8px 14px', fontWeight: 500, color: 'var(--color-text-dim)' }}>Bytes</th>
                  <th style={{ textAlign: 'right', padding: '8px 14px', fontWeight: 500, color: 'var(--color-text-dim)' }}>Packets</th>
                </tr>
              </thead>
              <tbody>
                {talkers.slice(0, 10).map((t, i) => (
                  <tr key={t.ip || i} style={{ borderBottom: '1px solid var(--color-border-light)' }}>
                    <td style={{ padding: '8px 14px', fontFamily: 'monospace', fontWeight: 500 }}>{t.ip}</td>
                    <td style={{ padding: '8px 14px', textAlign: 'right', color: 'var(--color-text-muted)' }}>
                      {t.bytes > 1024 * 1024 ? `${(t.bytes / 1024 / 1024).toFixed(1)} MB` : t.bytes > 1024 ? `${(t.bytes / 1024).toFixed(1)} KB` : `${t.bytes} B`}
                    </td>
                    <td style={{ padding: '8px 14px', textAlign: 'right', color: 'var(--color-text-muted)' }}>{t.packets?.toLocaleString() || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Anomalies */}
        <div style={{
          background: 'var(--color-surface)', borderRadius: 12,
          border: '1px solid var(--color-border)',
          boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
          overflow: 'hidden',
        }}>
          <div style={{
            padding: '14px 16px', borderBottom: '1px solid var(--color-border)',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <AlertTriangle size={15} color="var(--color-text-dim)" strokeWidth={1.8} />
            <span style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--color-text)' }}>Anomalies</span>
          </div>
          {anomalies.length === 0 ? (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--color-text-dim)', fontSize: 13 }}>
              No anomalies detected.
            </div>
          ) : (
            <div style={{ padding: 8 }}>
              {anomalies.slice(0, 10).map((a, i) => (
                <div key={a.id || i} style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '10px 12px', borderRadius: 8,
                  fontSize: 12.5, color: 'var(--color-text)',
                }}>
                  <AlertTriangle size={12} color={a.z_score > 5 ? 'var(--color-danger)' : 'var(--color-warning)'} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 500 }}>{a.description || a.type || 'Anomaly'}</div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 1 }}>
                      {a.device_ip || a.ip || ''} · z-score: {a.z_score?.toFixed(1) || '—'} · {a.timestamp ? new Date(a.timestamp).toLocaleString() : ''}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
