import { useState, useRef, useEffect } from 'react';
import { Scan, X, Loader2, Target, Zap, ChevronRight, Shield, Activity, Globe } from 'lucide-react';
import { useWS } from '../hooks/useWS';
import { api } from '../lib/api';

const profiles = [
  { id: 'quick', label: 'Quick Ping Sweep', desc: 'Ping scan + ARP discovery', icon: Zap },
  { id: 'stealth', label: 'Stealth SYN Scan', desc: 'Half-open TCP, OS/version detection', icon: Target },
  { id: 'full', label: 'Full Connect Scan', desc: 'Full TCP connect + service + OS detection', icon: Target },
  { id: 'vuln', label: 'Vulnerability Scan', desc: 'Full scan + NSE vuln scripts + CVE correlation', icon: Shield },
  { id: 'discovery', label: 'Network Discovery', desc: 'Broad subnet scan, no aggressive probes', icon: Activity },
] ;

const examples = ['192.168.1.0/24', '10.0.0.1', 'scanme.nmap.org', '192.168.1.1-100'];

function detectLocalSubnet() {
  // Try to get the local subnet from the backend which knows the machine's IP
  return fetch('/api/config').then(r => r.json()).then(data => {
    if (data.local_subnet) return data.local_subnet;
    if (data.network_range) return data.network_range;
    return null;
  }).catch(() => null);
}

function guessSubnetFromHostname() {
  // Fallback: use common default subnets
  const hostname = window.location.hostname;
  if (hostname.startsWith('192.168.')) {
    const parts = hostname.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  if (hostname.startsWith('10.')) {
    const parts = hostname.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  return '192.168.1.0/24';
}

export default function ScanButton() {
  const [open, setOpen] = useState(false);
  const [target, setTarget] = useState('');
  const [subnetDetecting, setSubnetDetecting] = useState(false);
  const [profile, setProfile] = useState('quick');
  const [duration, setDuration] = useState(30);
  const [traceHops, setTraceHops] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);
  const inputRef = useRef(null);
  const modalRef = useRef(null);
  const { connected } = useWS();

  const scanningId = useRef(null);
  const scanEvents = useWS();

  // Auto-detect local subnet when modal opens
  useEffect(() => {
    if (!open) return;
    setSubnetDetecting(true);
    detectLocalSubnet().then(subnet => {
      if (subnet) {
        setTarget(subnet);
      } else {
        setTarget(guessSubnetFromHostname());
      }
      setSubnetDetecting(false);
      if (inputRef.current) inputRef.current.focus();
    }).catch(() => {
      setTarget(guessSubnetFromHostname());
      setSubnetDetecting(false);
    });
  }, [open]);

  // Close on escape
  useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (e.key === 'Escape') setOpen(false); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open]);

  // Listen for scan.progress events to know when scan completes
  useEffect(() => {
    if (!scanEvents.lastEvent || !scanning) return;
    const ev = scanEvents.lastEvent;
    if (ev.type === 'scan.progress' && ev.scanning === false && scanningId.current) {
      setScanning(false);
      scanningId.current = null;
      setSuccessMsg('Scan completed');
      setTimeout(() => setSuccessMsg(null), 4000);
    }
  }, [scanEvents.lastEvent, scanning]);

  async function handleStart() {
    if (!target.trim()) return;
    setError(null);
    setScanning(true);

    try {
      const result = await api.scan.start(target.trim(), profile, {
        duration: profile === 'full' || profile === 'vuln' ? duration : undefined,
        trace_hops: traceHops || undefined,
      });
      if (result.scan_id) scanningId.current = result.scan_id;
      setSuccessMsg(`Scan queued: ${target.trim()}`);
      setTimeout(() => { setOpen(false); setSuccessMsg(null); }, 1500);
    } catch (err) {
      setError(err.message || 'Failed to start scan');
      setScanning(false);
    }
  }

  return (
    <>
      {/* ── Floating Action Button ────────────────────────────────────── */}
      <button
        onClick={() => setOpen(true)}
        disabled={scanning}
        title="New Scan"
        style={{
          position: 'fixed', bottom: 28, right: 28,
          zIndex: 50,
          width: 54, height: 54, borderRadius: 16,
          background: 'var(--color-accent)',
          color: '#fff',
          border: 'none',
          cursor: scanning ? 'not-allowed' : 'pointer',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 4px 16px var(--color-accent-glow), 0 1px 3px rgba(0,0,0,0.08)',
          transition: 'all 0.2s ease',
          opacity: scanning ? 0.7 : 1,
          animation: open ? 'none' : 'fab-pulse 2s ease-in-out infinite',
        }}
        onMouseEnter={e => { if (!scanning) e.currentTarget.style.transform = 'scale(1.06)'; }}
        onMouseLeave={e => { if (!scanning) e.currentTarget.style.transform = 'scale(1)'; }}
      >
        {scanning ? (
          <Loader2 size={22} className="animate-spin" />
        ) : (
          <Scan size={22} strokeWidth={2} />
        )}
      </button>

      {/* ── Modal Backdrop ────────────────────────────────────────────── */}
      {open && (
        <div
          onClick={() => { if (!scanning) setOpen(false); }}
          style={{
            position: 'fixed', inset: 0, zIndex: 100,
            background: 'rgba(0,0,0,0.25)',
            backdropFilter: 'blur(4px)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
        >
          {/* Modal */}
          <div
            ref={modalRef}
            onClick={e => e.stopPropagation()}
            className="animate-slide-up"
            style={{
              background: 'var(--color-surface)',
              borderRadius: 16,
              border: '1px solid var(--color-border)',
              width: 480, maxWidth: '90vw',
              maxHeight: '90vh', overflow: 'auto',
              boxShadow: '0 20px 60px rgba(0,0,0,0.12), 0 1px 4px rgba(0,0,0,0.04)',
            }}
          >
            {/* Header */}
            <div style={{
              padding: '20px 24px',
              borderBottom: '1px solid var(--color-border)',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Scan size={18} color="var(--color-accent)" strokeWidth={1.8} />
                <span style={{ fontWeight: 600, fontSize: 15, color: 'var(--color-text)' }}>
                  New Scan
                </span>
              </div>
              {!scanning && (
                <button onClick={() => setOpen(false)} style={{
                  background: 'var(--color-surface-2)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 6, padding: 4, cursor: 'pointer',
                  display: 'flex', color: 'var(--color-text-muted)',
                  transition: 'all 0.15s',
                }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--color-surface-3)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'var(--color-surface-2)'}
                >
                  <X size={14} />
                </button>
              )}
            </div>

            {/* Body */}
            <div style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Target input */}
              <div>
                <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-muted)', marginBottom: 6, display: 'block' }}>
                  Target <span style={{ color: 'var(--color-accent)' }}>*</span>
                </label>
                <div style={{ position: 'relative', display: 'flex', gap: 6, alignItems: 'center' }}>
                  <input
                    ref={inputRef}
                    type="text"
                    placeholder="IP, CIDR range, hostname, or domain..."
                    value={target}
                    onChange={e => { setTarget(e.target.value); setError(null); }}
                    onKeyDown={e => { if (e.key === 'Enter' && target.trim()) handleStart(); }}
                    disabled={scanning}
                    style={{
                      flex: 1,
                      padding: '10px 12px',
                      borderRadius: 8,
                      border: `1px solid ${error ? 'var(--color-danger)' : 'var(--color-border)'}`,
                      background: 'var(--color-surface-2)',
                      fontSize: 14,
                      color: 'var(--color-text)',
                      outline: 'none',
                      transition: 'border-color 0.15s',
                    }}
                    onFocus={e => { e.target.style.borderColor = 'var(--color-accent)'; }}
                    onBlur={e => { e.target.style.borderColor = error ? 'var(--color-danger)' : 'var(--color-border)'; }}
                  />
                  <button
                    onClick={() => {
                      setSubnetDetecting(true);
                      detectLocalSubnet().then(subnet => {
                        if (subnet) setTarget(subnet);
                        else setTarget(guessSubnetFromHostname());
                        setSubnetDetecting(false);
                      }).catch(() => {
                        setTarget(guessSubnetFromHostname());
                        setSubnetDetecting(false);
                      });
                    }}
                    disabled={scanning || subnetDetecting}
                    title="Detect local subnet"
                    style={{
                      padding: '10px 10px', borderRadius: 8,
                      border: '1px solid var(--color-border)',
                      background: 'var(--color-surface-2)',
                      cursor: scanning || subnetDetecting ? 'not-allowed' : 'pointer',
                      display: 'flex', alignItems: 'center',
                      color: 'var(--color-accent)',
                      transition: 'all 0.15s',
                      flexShrink: 0,
                    }}
                    onMouseEnter={e => { if (!scanning && !subnetDetecting) e.currentTarget.style.background = 'var(--color-accent-bg)'; }}
                    onMouseLeave={e => { if (!scanning && !subnetDetecting) e.currentTarget.style.background = 'var(--color-surface-2)'; }}
                  >
                    {subnetDetecting ? <Loader2 size={14} className="animate-spin" /> : <Globe size={14} />}
                  </button>
                </div>
                {/* Quick examples */}
                <div style={{ display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }}>
                  {examples.map(ex => (
                    <button key={ex} onClick={() => setTarget(ex)}
                      style={{
                        padding: '3px 8px', borderRadius: 4, border: '1px solid var(--color-border-light)',
                        background: 'var(--color-surface-2)', fontSize: 11,
                        color: 'var(--color-text-dim)', cursor: 'pointer',
                        transition: 'all 0.12s',
                      }}
                      onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--color-accent)'; e.currentTarget.style.color = 'var(--color-accent)'; }}
                      onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--color-border-light)'; e.currentTarget.style.color = 'var(--color-text-dim)'; }}
                    >
                      {ex}
                    </button>
                  ))}
                </div>
                {error && <p style={{ color: 'var(--color-danger)', fontSize: 12, margin: '6px 0 0' }}>{error}</p>}
              </div>

              {/* Profile selection */}
              <div>
                <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-muted)', marginBottom: 8, display: 'block' }}>
                  Scan Profile
                </label>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {profiles.map(p => {
                    const active = profile === p.id;
                    const Icon = p.icon;
                    return (
                      <button key={p.id} onClick={() => setProfile(p.id)} disabled={scanning}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 10,
                          padding: '10px 12px', borderRadius: 8, border: 'none',
                          background: active ? 'var(--color-accent-bg)' : 'var(--color-surface-2)',
                          cursor: scanning ? 'not-allowed' : 'pointer',
                          textAlign: 'left',
                          opacity: scanning ? 0.6 : 1,
                          transition: 'all 0.12s',
                        }}
                        onMouseEnter={e => { if (!active && !scanning) e.currentTarget.style.background = 'var(--color-surface-3)'; }}
                        onMouseLeave={e => { if (!active && !scanning) e.currentTarget.style.background = 'var(--color-surface-2)'; }}
                      >
                        <Icon size={15} color={active ? 'var(--color-accent)' : 'var(--color-text-dim)'} strokeWidth={1.8} />
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 13, fontWeight: active ? 500 : 400, color: active ? 'var(--color-accent)' : 'var(--color-text)' }}>
                            {p.label}
                          </div>
                          <div style={{ fontSize: 11.5, color: 'var(--color-text-dim)', marginTop: 1 }}>{p.desc}</div>
                        </div>
                        {active && <ChevronRight size={14} color="var(--color-accent)" />}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Advanced options */}
              <div style={{
                padding: '12px', borderRadius: 8,
                background: 'var(--color-surface-2)',
                border: '1px solid var(--color-border-light)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                  {/* Duration */}
                  <div style={{ flex: 1, minWidth: 120 }}>
                    <label style={{ fontSize: 11.5, color: 'var(--color-text-dim)', display: 'block', marginBottom: 4 }}>
                      Duration (s)
                    </label>
                    <input type="number" min={10} max={600} value={duration}
                      onChange={e => setDuration(Math.min(600, Math.max(10, parseInt(e.target.value) || 30)))}
                      disabled={scanning}
                      style={{
                        width: '100%', padding: '6px 10px', borderRadius: 6,
                        border: '1px solid var(--color-border)',
                        background: scanning ? 'var(--color-surface-3)' : 'var(--color-surface)',
                        fontSize: 13, color: 'var(--color-text)', outline: 'none',
                      }} />
                  </div>
                  {/* Trace hops */}
                  <label style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    fontSize: 12, color: 'var(--color-text-muted)', cursor: scanning ? 'not-allowed' : 'pointer',
                    paddingTop: 16,
                  }}>
                    <input type="checkbox" checked={traceHops}
                      onChange={e => setTraceHops(e.target.checked)}
                      disabled={scanning}
                      style={{ accentColor: 'var(--color-accent)' }} />
                    Trace hops
                  </label>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div style={{
              padding: '16px 24px',
              borderTop: '1px solid var(--color-border)',
              display: 'flex', justifyContent: 'flex-end', gap: 8,
            }}>
              {!scanning && (
                <button onClick={() => setOpen(false)}
                  style={{
                    padding: '8px 16px', borderRadius: 8, border: '1px solid var(--color-border)',
                    background: 'var(--color-surface)', cursor: 'pointer',
                    fontSize: 13, color: 'var(--color-text-muted)',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--color-surface-2)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'var(--color-surface)'}
                >
                  Cancel
                </button>
              )}
              <button onClick={handleStart} disabled={!target.trim() || scanning}
                style={{
                  padding: '8px 20px', borderRadius: 8, border: 'none',
                  background: !target.trim() || scanning ? 'var(--color-border)' : 'var(--color-accent)',
                  color: !target.trim() || scanning ? 'var(--color-text-dim)' : '#fff',
                  cursor: !target.trim() || scanning ? 'not-allowed' : 'pointer',
                  fontSize: 13, fontWeight: 500,
                  display: 'flex', alignItems: 'center', gap: 6,
                  transition: 'all 0.15s',
                }}
                onMouseEnter={e => {
                  if (target.trim() && !scanning) e.currentTarget.style.opacity = '0.85';
                }}
                onMouseLeave={e => {
                  if (target.trim() && !scanning) e.currentTarget.style.opacity = '1';
                }}
              >
                {scanning ? (
                  <><Loader2 size={14} className="animate-spin" /> Scanning...</>
                ) : (
                  <><Scan size={14} /> Start Scan</>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Success toast ────────────────────────────────────────────── */}
      {successMsg && (
        <div className="toast-enter" style={{
          position: 'fixed', bottom: 90, right: 28,
          zIndex: 60,
          padding: '10px 16px', borderRadius: 8,
          background: 'var(--color-accent)', color: '#fff',
          fontSize: 13, fontWeight: 500,
          boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
        }}>
          {successMsg}
        </div>
      )}
    </>
  );
}
