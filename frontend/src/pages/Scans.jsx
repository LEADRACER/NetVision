import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { useWS } from '../hooks/useWS';
import { Clock, Play, Square, CheckCircle, XCircle, Loader2, History, ListOrdered } from 'lucide-react';

const statusColors = {
  completed: 'var(--color-accent)',
  running: 'var(--color-info)',
  failed: 'var(--color-danger)',
  cancelled: 'var(--color-text-dim)',
  queued: 'var(--color-warning)',
};

export default function Scans() {
  const [history, setHistory] = useState([]);
  const [queue, setQueue] = useState([]);
  const [scanning, setScanning] = useState(false);
  const ws = useWS();

  useEffect(() => {
    api.scan.history(30).then(data => setHistory(data.scans || data || [])).catch(() => {});
    api.scan.queue().then(data => setQueue(data.queue || [])).catch(() => {});
    api.health.scan().then(h => setScanning(h.is_scanning)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!ws.lastEvent) return;
    const ev = ws.lastEvent;
    if (ev.type === 'scan.progress') {
      setScanning(ev.scanning);
      if (!ev.scanning) {
        api.scan.history(30).then(data => setHistory(data.scans || data || [])).catch(() => {});
        api.scan.queue().then(data => setQueue(data.queue || [])).catch(() => {});
      }
    }
  }, [ws.lastEvent]);

  const handleStop = () => {
    api.scan.stop().then(() => setScanning(false)).catch(() => {});
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 600, color: 'var(--color-text)', margin: 0 }}>
          Scans
        </h1>
        <p style={{ fontSize: 13.5, color: 'var(--color-text-muted)', margin: '4px 0 0' }}>
          {scanning ? 'Active scan in progress' : 'No active scan'}
        </p>
      </div>

      {/* Active scan indicator */}
      {scanning && (
        <div style={{
          padding: '12px 16px', borderRadius: 10,
          background: 'var(--color-info-bg)',
          border: '1px solid var(--color-info)',
          display: 'flex', alignItems: 'center', gap: 10,
          fontSize: 13.5, color: 'var(--color-info)',
          animation: 'fade-in 0.3s ease-out',
        }}>
          <Loader2 size={16} className="animate-spin" />
          <span style={{ flex: 1, fontWeight: 500 }}>Scan in progress</span>
          <button onClick={handleStop}
            style={{
              padding: '6px 14px', borderRadius: 6,
              background: 'var(--color-danger)', color: '#fff',
              border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: 500,
              display: 'flex', alignItems: 'center', gap: 6,
            }}>
            <Square size={12} /> Stop
          </button>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, alignItems: 'start' }}>
        {/* Queue */}
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
            <ListOrdered size={15} color="var(--color-text-dim)" strokeWidth={1.8} />
            <span style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--color-text)' }}>Queue</span>
            <span style={{
              marginLeft: 'auto', fontSize: 11.5, padding: '2px 8px', borderRadius: 10,
              background: 'var(--color-surface-2)', color: 'var(--color-text-dim)',
            }}>
              {queue.length} pending
            </span>
          </div>
          <div style={{ padding: 8 }}>
            {queue.length === 0 ? (
              <div style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--color-text-dim)', fontSize: 13 }}>
                Queue is empty. Start a scan from the + button.
              </div>
            ) : queue.map((item, i) => (
              <div key={item.scan_id || i} style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '10px 12px', borderRadius: 8,
                fontSize: 13, color: 'var(--color-text)',
              }}>
                <Play size={12} color="var(--color-warning)" />
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 500 }}>{item.target || 'Unknown target'}</div>
                  <div style={{ fontSize: 11.5, color: 'var(--color-text-dim)', marginTop: 1 }}>
                    {item.profile || '—'} · priority {item.priority || 'normal'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* History */}
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
            <History size={15} color="var(--color-text-dim)" strokeWidth={1.8} />
            <span style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--color-text)' }}>History</span>
          </div>
          <div style={{ padding: 8 }}>
            {history.length === 0 ? (
              <div style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--color-text-dim)', fontSize: 13 }}>
                No scan history yet.
              </div>
            ) : history.slice(0, 20).map((s, i) => {
              const color = statusColors[s.status] || 'var(--color-text-dim)';
              return (
                <div key={s.scan_id || i} style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '10px 12px', borderRadius: 8,
                  fontSize: 13, color: 'var(--color-text)',
                }}>
                  <div style={{
                    width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                    background: color,
                  }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {s.target || 'Unknown'}
                    </div>
                    <div style={{ fontSize: 11.5, color: 'var(--color-text-dim)', marginTop: 1 }}>
                      {s.profile || '—'} · {s.devices_found || 0} devices · {s.status || 'unknown'}
                    </div>
                  </div>
                  <Clock size={12} color="var(--color-text-dim)" />
                  <span style={{ fontSize: 11.5, color: 'var(--color-text-dim)' }}>
                    {s.duration ? `${s.duration}s` : ''}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
