import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { useWS } from '../hooks/useWS';
import { Search, Wifi, WifiOff, Clock, Monitor, Smartphone } from 'lucide-react';

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [search, setSearch] = useState('');
  const ws = useWS();

  useEffect(() => {
    api.devices.list().then(data => setDevices(data.devices || [])).catch(() => {});
  }, []);

  // Refresh on scan progress
  useEffect(() => {
    if (ws.lastEvent?.type === 'scan.progress') {
      api.devices.list().then(data => setDevices(data.devices || [])).catch(() => {});
    }
  }, [ws.lastEvent]);

  const filtered = devices.filter(d =>
    !search || d.ip?.includes(search) || d.mac?.toLowerCase().includes(search.toLowerCase()) || d.hostname?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 600, color: 'var(--color-text)', margin: 0 }}>
            Devices
          </h1>
          <p style={{ fontSize: 13.5, color: 'var(--color-text-muted)', margin: '4px 0 0' }}>
            {devices.length} device{devices.length !== 1 ? 's' : ''} discovered
          </p>
        </div>
        <div style={{ position: 'relative' }}>
          <Search size={14} color="var(--color-text-dim)" style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)' }} />
          <input type="text" placeholder="Search IP, MAC, hostname..." value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              padding: '8px 12px 8px 30px', borderRadius: 8,
              border: '1px solid var(--color-border)',
              background: 'var(--color-surface)',
              fontSize: 13, color: 'var(--color-text)',
              outline: 'none', width: 240,
              transition: 'border-color 0.15s',
            }}
            onFocus={e => e.target.style.borderColor = 'var(--color-accent)'}
            onBlur={e => e.target.style.borderColor = 'var(--color-border)'}
          />
        </div>
      </div>

      {/* Device list */}
      <div style={{
        background: 'var(--color-surface)', borderRadius: 12,
        border: '1px solid var(--color-border)',
        boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
        overflow: 'hidden',
      }}>
        {filtered.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--color-text-dim)', fontSize: 13 }}>
            {search ? 'No devices match your search.' : 'No devices discovered yet. Run a scan to discover devices.'}
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--color-border)', background: 'var(--color-surface-2)' }}>
                <th style={{ textAlign: 'left', padding: '10px 14px', fontWeight: 500, color: 'var(--color-text-dim)', fontSize: 11.5 }}>Status</th>
                <th style={{ textAlign: 'left', padding: '10px 14px', fontWeight: 500, color: 'var(--color-text-dim)', fontSize: 11.5 }}>IP Address</th>
                <th style={{ textAlign: 'left', padding: '10px 14px', fontWeight: 500, color: 'var(--color-text-dim)', fontSize: 11.5 }}>MAC Address</th>
                <th style={{ textAlign: 'left', padding: '10px 14px', fontWeight: 500, color: 'var(--color-text-dim)', fontSize: 11.5 }}>Hostname</th>
                <th style={{ textAlign: 'left', padding: '10px 14px', fontWeight: 500, color: 'var(--color-text-dim)', fontSize: 11.5 }}>Vendor</th>
                <th style={{ textAlign: 'left', padding: '10px 14px', fontWeight: 500, color: 'var(--color-text-dim)', fontSize: 11.5 }}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(d => {
                const isUp = d.health?.status === 'up';
                return (
                  <tr key={d.ip} style={{
                    borderBottom: '1px solid var(--color-border-light)',
                    transition: 'background 0.1s',
                  }}
                    onMouseEnter={e => e.currentTarget.style.background = 'var(--color-surface-2)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <td style={{ padding: '12px 14px' }}>
                      <div style={{
                        display: 'flex', alignItems: 'center', gap: 6,
                        color: isUp ? 'var(--color-accent)' : 'var(--color-text-dim)',
                      }}>
                        {isUp ? <Wifi size={14} strokeWidth={2} /> : <WifiOff size={14} />}
                        <span style={{ fontSize: 12 }}>{isUp ? 'Up' : 'Unknown'}</span>
                      </div>
                    </td>
                    <td style={{ padding: '12px 14px', fontWeight: 500, color: 'var(--color-text)', fontFamily: 'monospace', fontSize: 12.5 }}>{d.ip}</td>
                    <td style={{ padding: '12px 14px', color: 'var(--color-text-muted)', fontFamily: 'monospace', fontSize: 12 }}>{d.mac || '—'}</td>
                    <td style={{ padding: '12px 14px', color: 'var(--color-text)' }}>{d.hostname || d.domain || '—'}</td>
                    <td style={{ padding: '12px 14px', color: 'var(--color-text-muted)' }}>{d.vendor || '—'}</td>
                    <td style={{ padding: '12px 14px', color: 'var(--color-text-dim)', fontSize: 12 }}>
                      {d.last_seen ? new Date(d.last_seen).toLocaleString() : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
