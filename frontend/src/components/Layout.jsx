import { useState } from 'react';
import { useWS } from '../hooks/useWS';
import {
  Activity, Wifi, Scan, Shield, Radio, Settings, Menu, X,
} from 'lucide-react';

const navItems = [
  { path: '/', label: 'Overview', icon: Activity },
  { path: '/devices', label: 'Devices', icon: Wifi },
  { path: '/scans', label: 'Scans', icon: Scan },
  { path: '/vulnerabilities', label: 'Vulnerabilities', icon: Shield },
  { path: '/capture', label: 'Capture', icon: Radio },
  { path: '/settings', label: 'Settings', icon: Settings },
];

export default function Layout({ currentPath, onNavigate, children }) {
  const { connected } = useWS();
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'transparent' }}>

      {/* ── Sidebar ────────────────────────────────────────────────────── */}
      <aside style={{
        width: sidebarOpen ? 220 : 56,
        background: 'var(--color-surface)',
        borderRight: '1px solid var(--color-border)',
        display: 'flex',
        flexDirection: 'column',
        transition: 'width 0.2s ease, opacity 0.2s ease',
        flexShrink: 0,
        position: 'sticky',
        top: 0,
        height: '100vh',
      }}>
        {/* Logo */}
        <div style={{
          padding: '20px 16px',
          borderBottom: '1px solid var(--color-border)',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
        }}>
          <div style={{
            width: 28, height: 28, borderRadius: 7,
            background: 'var(--color-accent-bg)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Activity size={16} color="var(--color-accent)" />
          </div>
          {sidebarOpen && (
            <span style={{ fontWeight: 600, fontSize: 15, color: 'var(--color-text)', letterSpacing: '-0.01em' }}>
              NetVision
            </span>
          )}
        </div>

        {/* Nav items */}
        <nav style={{ padding: '8px 6px', flex: 1, display: 'flex', flexDirection: 'column', gap: 2 }}>
          {navItems.map(item => {
            const active = currentPath === item.path;
            return (
              <button key={item.path} onClick={() => onNavigate(item.path)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '9px 10px', borderRadius: 6, border: 'none',
                  background: active ? 'var(--color-accent-bg)' : 'transparent',
                  color: active ? 'var(--color-accent)' : 'var(--color-text-muted)',
                  cursor: 'pointer', fontSize: 13.5, fontWeight: active ? 500 : 400,
                  transition: 'all 0.12s ease', width: '100%',
                  whiteSpace: 'nowrap',
                }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--color-surface-2)'; }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent'; }}
              >
                <item.icon size={17} strokeWidth={1.8} />
                {sidebarOpen && <span>{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* Connection indicator */}
        <div style={{
          padding: '10px 14px', borderTop: '1px solid var(--color-border)',
          display: 'flex', alignItems: 'center', gap: 8, fontSize: 11.5, color: 'var(--color-text-dim)',
        }}>
          <div style={{
            width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
            background: connected ? 'var(--color-accent)' : 'var(--color-text-dim)',
            boxShadow: connected ? '0 0 5px var(--color-accent-glow)' : 'none',
            transition: 'all 0.3s',
          }} />
          {sidebarOpen && <span>{connected ? 'Connected' : 'Reconnecting...'}</span>}
        </div>

        {/* Collapse toggle */}
        <button onClick={() => setSidebarOpen(!sidebarOpen)}
          style={{
            padding: '8px 14px', borderTop: '1px solid var(--color-border)',
            background: 'transparent', border: 'none', color: 'var(--color-text-dim)',
            cursor: 'pointer', display: 'flex', alignItems: 'center',
            justifyContent: sidebarOpen ? 'flex-end' : 'center', fontSize: 12,
          }}>
          {sidebarOpen ? <X size={13} /> : <Menu size={13} />}
        </button>
      </aside>

      {/* ── Main content ────────────────────────────────────────────────── */}
      <main style={{
        flex: 1, display: 'flex', flexDirection: 'column',
        overflow: 'auto', padding: '24px 32px', paddingBottom: 96,
        maxWidth: 1200, width: '100%', margin: '0 auto',
      }}>
        {children}
      </main>
    </div>
  );
}
