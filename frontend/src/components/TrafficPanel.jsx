import React, { useState, useEffect } from 'react';

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const TrafficPanel = () => {
  const [tab, setTab] = useState('http');
  const [httpLogs, setHttpLogs] = useState([]);
  const [dnsLogs, setDnsLogs] = useState([]);
  const [tlsLogs, setTlsLogs] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchData = () => {
    setLoading(true);
    Promise.all([
      fetch(`${API}/capture/http-logs`).then(r=>r.json()).catch(()=>[]),
      fetch(`${API}/capture/dns-logs`).then(r=>r.json()).catch(()=>[]),
      fetch(`${API}/capture/tls-logs`).then(r=>r.json()).catch(()=>[]),
      fetch(`${API}/capture/analysis-summary`).then(r=>r.json()).catch(()=>null),
    ]).then(([http, dns, tls, sum]) => {
      setHttpLogs(http);
      setDnsLogs(dns);
      setTlsLogs(tls);
      setSummary(sum);
      setLoading(false);
    });
  };

  useEffect(() => { fetchData(); const iv = setInterval(fetchData, 10000); return () => clearInterval(iv); }, []);

  const TABS = [
    {id:'http', label:`HTTP (${summary?.http_requests||httpLogs.length||0})`},
    {id:'dns', label:`DNS (${summary?.dns_queries||dnsLogs.length||0})`},
    {id:'tls', label:`TLS (${summary?.tls_handshakes||tlsLogs.length||0})`},
  ];

  const renderHttp = () => (
    <div style={{maxHeight:'600px',overflowY:'auto'}}>
      {httpLogs.length === 0
        ? <p style={{color:'#71717a',fontSize:'0.8rem'}}>No HTTP logs yet</p>
        : httpLogs.map((l, i) => (
            <div key={i} className="p5-card" style={{fontSize:'0.75rem'}}>
              <div className="p5-card-row">
                <span><b>{l.method || 'RESP'}</b> {l.uri || l.status_code}</span>
                <span className={`p5-pill ${l.log_type==='request'?'p5-normal':'p5-low'}`}>{l.log_type}</span>
              </div>
              <div className="p5-card-meta">
                <span>{l.src_ip} → {l.dst_ip}</span>
                {l.host && <span>Host: {l.host}</span>}
              </div>
              <div className="p5-card-meta">
                <span style={{color:'#71717a'}}>{new Date(l.timestamp).toLocaleString()}</span>
              </div>
            </div>
          ))
      }
    </div>
  );

  const renderDns = () => (
    <div style={{maxHeight:'600px',overflowY:'auto'}}>
      {dnsLogs.length === 0
        ? <p style={{color:'#71717a',fontSize:'0.8rem'}}>No DNS logs yet</p>
        : dnsLogs.map((l, i) => (
            <div key={i} className="p5-card" style={{fontSize:'0.75rem'}}>
              <div className="p5-card-row">
                <span><b>{l.query_name}</b></span>
                <span className={`p5-pill ${l.is_response?'p5-normal':'p5-low'}`}>{l.is_response ? 'RESPONSE' : 'QUERY'}</span>
              </div>
              <div className="p5-card-meta">
                <span>{l.src_ip} → {l.dst_ip}</span>
                <span>Type: {l.query_type}</span>
              </div>
              <div className="p5-card-meta">
                <span style={{color:'#71717a'}}>{new Date(l.timestamp).toLocaleString()}</span>
              </div>
            </div>
          ))
      }
    </div>
  );

  const renderTls = () => (
    <div style={{maxHeight:'600px',overflowY:'auto'}}>
      {tlsLogs.length === 0
        ? <p style={{color:'#71717a',fontSize:'0.8rem'}}>No TLS logs yet</p>
        : tlsLogs.map((l, i) => (
            <div key={i} className="p5-card" style={{fontSize:'0.75rem'}}>
              <div className="p5-card-row">
                <span><b>{l.sni || '(no SNI)'}</b></span>
                <span className="p5-pill">{l.version || 'TLS'}</span>
              </div>
              <div className="p5-card-meta">
                <span>{l.src_ip} → {l.dst_ip}</span>
                <span>Cipher: {l.cipher_suite}</span>
              </div>
              <div className="p5-card-meta">
                <span style={{color:'#71717a'}}>{new Date(l.timestamp).toLocaleString()}</span>
              </div>
            </div>
          ))
      }
    </div>
  );

  return (
    <div>
      <h3 className="section-title">TRAFFIC LOGS</h3>

      {/* Summary cards */}
      {summary && (
        <div className="stats-grid" style={{marginBottom:'1.5rem'}}>
          <div className="stat-box"><p className="stat-label">SNAPSHOTS</p><b>{summary.total_snapshots}</b></div>
          <div className="stat-box"><p className="stat-label">HTTP</p><b>{summary.http_requests}</b></div>
          <div className="stat-box"><p className="stat-label">DNS</p><b>{summary.dns_queries}</b></div>
          <div className="stat-box"><p className="stat-label">TLS</p><b>{summary.tls_handshakes}</b></div>
        </div>
      )}

      {/* Tab buttons */}
      <div style={{display:'flex',gap:'0.5rem',marginBottom:'1rem',flexWrap:'wrap'}}>
        {TABS.map(t => (
          <button key={t.id} className={`p5-tab-btn ${tab===t.id?'active':''}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {loading && <p style={{color:'#71717a',fontSize:'0.8rem'}}>Loading...</p>}
      {!loading && tab === 'http' && renderHttp()}
      {!loading && tab === 'dns' && renderDns()}
      {!loading && tab === 'tls' && renderTls()}
    </div>
  );
};

export default TrafficPanel;
