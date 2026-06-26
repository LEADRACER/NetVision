import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { useWS } from '../hooks/useWS';
import { Shield, AlertTriangle, Info, ExternalLink, Search } from 'lucide-react';

const severityColors = {
  critical: { bg: 'var(--color-danger-bg)', text: 'var(--color-danger)', label: 'Critical' },
  high: { bg: 'var(--color-warning-bg)', text: 'var(--color-warning)', label: 'High' },
  medium: { bg: 'var(--color-info-bg)', text: 'var(--color-info)', label: 'Medium' },
  low: { bg: 'var(--color-accent-bg)', text: 'var(--color-accent)', label: 'Low' },
};

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([]);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const ws = useWS();

  useEffect(() => {
    api.vulnerabilities.list().then(data => {
      setVulns(data.vulnerabilities || data || []);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (ws.lastEvent?.type === 'vuln.found') {
      api.vulnerabilities.list().then(data => {
        setVulns(data.vulnerabilities || data || []);
      }).catch(() => {});
    }
  }, [ws.lastEvent]);

  const filtered = vulns.filter(v => {
    if (filter !== 'all' && v.severity?.toLowerCase() !== filter) return false;
    if (search) {
      const q = search.toLowerCase();
      return v.cve_id?.toLowerCase().includes(q) || v.description?.toLowerCase().includes(q) || v.service?.toLowerCase().includes(q);
    }
    return true;
  });

  const counts = { all: vulns.length, critical: 0, high: 0, medium: 0, low: 0 };
  vulns.forEach(v => { const s = v.severity?.toLowerCase(); if (counts[s] !== undefined) counts[s]++; });

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 600, color: 'var(--color-text)', margin: 0 }}>
            Vulnerabilities
          </h1>
          <p style={{ fontSize: 13.5, color: 'var(--color-text-muted)', margin: '4px 0 0' }}>
            {vulns.length} CVE{vulns.length !== 1 ? 's' : ''} discovered
          </p>
        </div>
        <div style={{ position: 'relative' }}>
          <Search size={14} color="var(--color-text-dim)" style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)' }} />
          <input type="text" placeholder="Search CVE ID, description..."
            value={search} onChange={e => setSearch(e.target.value)}
            style={{
              padding: '8px 12px 8px 30px', borderRadius: 8,
              border: '1px solid var(--color-border)',
              background: 'var(--color-surface)',
              fontSize: 13, color: 'var(--color-text)',
              outline: 'none', width: 220,
              transition: 'border-color 0.15s',
            }}
            onFocus={e => e.target.style.borderColor = 'var(--color-accent)'}
            onBlur={e => e.target.style.borderColor = 'var(--color-border)'}
          />
        </div>
      </div>

      {/* Severity filter pills */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {Object.entries(counts).map(([key, count]) => {
          const sev = severityColors[key];
          const active = filter === key;
          return (
            <button key={key} onClick={() => setFilter(key)}
              style={{
                padding: '6px 14px', borderRadius: 20,
                border: `1px solid ${active ? 'var(--color-accent)' : 'var(--color-border)'}`,
                background: active ? 'var(--color-accent-bg)' : 'var(--color-surface)',
                color: active ? 'var(--color-accent)' : 'var(--color-text-muted)',
                cursor: 'pointer', fontSize: 12.5, fontWeight: 500,
                display: 'flex', alignItems: 'center', gap: 6,
                transition: 'all 0.12s',
              }}>
              {key === 'all' ? <Shield size={13} /> : <AlertTriangle size={13} />}
              {key.charAt(0).toUpperCase() + key.slice(1)}
              <span style={{
                padding: '1px 6px', borderRadius: 8,
                background: active ? 'var(--color-accent-bg)' : 'var(--color-surface-2)',
                fontSize: 11,
              }}>{count}</span>
            </button>
          );
        })}
      </div>

      {/* CVE list */}
      <div style={{
        background: 'var(--color-surface)', borderRadius: 12,
        border: '1px solid var(--color-border)',
        boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
        overflow: 'hidden',
      }}>
        {filtered.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--color-text-dim)', fontSize: 13 }}>
            {search || filter !== 'all' ? 'No matching vulnerabilities.' : 'No vulnerabilities found. Run a vulnerability scan to discover CVEs.'}
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {filtered.map((v, i) => {
              const sev = severityColors[v.severity?.toLowerCase()] || severityColors.low;
              return (
                <div key={v.cve_id || v.id || i} style={{
                  display: 'flex', alignItems: 'flex-start', gap: 12,
                  padding: '14px 16px',
                  borderBottom: i < filtered.length - 1 ? '1px solid var(--color-border-light)' : 'none',
                  transition: 'background 0.1s',
                }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--color-surface-2)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <div style={{
                    padding: '3px 8px', borderRadius: 6,
                    background: sev.bg, color: sev.text,
                    fontSize: 11, fontWeight: 600, flexShrink: 0,
                    minWidth: 52, textAlign: 'center',
                  }}>{sev.label}</div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--color-text)', fontFamily: 'monospace' }}>
                      {v.cve_id || 'Unknown CVE'}
                    </div>
                    <div style={{ fontSize: 12.5, color: 'var(--color-text-muted)', marginTop: 3, lineHeight: 1.4 }}>
                      {v.description || 'No description'}
                    </div>
                    <div style={{ display: 'flex', gap: 12, marginTop: 6, fontSize: 11.5, color: 'var(--color-text-dim)' }}>
                      {v.cvss_score && <span>CVSS: {v.cvss_score}</span>}
                      {v.service && <span>Service: {v.service}</span>}
                      {v.device_ip && <span>Device: {v.device_ip}</span>}
                    </div>
                  </div>
                  <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noopener noreferrer"
                    style={{ color: 'var(--color-text-dim)', display: 'flex', padding: 4 }}>
                    <ExternalLink size={13} />
                  </a>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
