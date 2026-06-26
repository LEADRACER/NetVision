import React, { useState, useEffect } from 'react';

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const SecurityPanel = () => {
  const [tab, setTab] = useState('anomalies');
  const [anomalies, setAnomalies] = useState([]);
  const [suspiciousDNS, setSuspiciousDNS] = useState([]);
  const [rogueEvents, setRogueEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = () => {
    setLoading(true);
    Promise.all([
      fetch(`${API}/capture/anomalies`).then(r=>r.json()).catch(()=>[]),
      fetch(`${API}/capture/suspicious-dns`).then(r=>r.json()).catch(()=>[]),
      fetch(`${API}/capture/rogue-events`).then(r=>r.json()).catch(()=>[]),
    ]).then(([a, d, r]) => {
      setAnomalies(a);
      setSuspiciousDNS(d);
      setRogueEvents(r);
      setLoading(false);
    });
  };

  useEffect(() => { fetchData(); const iv = setInterval(fetchData, 10000); return () => clearInterval(iv); }, []);

  const renderAnomalies = () => (
    <div style={{maxHeight:'600px',overflowY:'auto'}}>
      {anomalies.length === 0
        ? <p style={{color:'#71717a',fontSize:'0.8rem'}}>No anomalies detected</p>
        : anomalies.map((a, i) => (
            <div key={i} className="p5-card" style={{borderLeft:`4px solid ${a.severity==='high'?'#ef4444':a.severity==='medium'?'#f97316':'#eab308'}`}}>
              <div className="p5-card-row">
                <b>{a.anomaly_type}</b>
                <span className={`p5-pill ${a.severity==='high'?'p5-critical':a.severity==='medium'?'p5-high':'p5-normal'}`}>{a.severity}</span>
              </div>
              <div className="p5-card-meta">
                {a.description && <span>{a.description}</span>}
              </div>
              <div className="p5-card-meta">
                {a.src_ip && <span>Source: {a.src_ip}</span>}
                {a.dst_ip && <span>Dest: {a.dst_ip}</span>}
                {a.score !== undefined && <span>Score: {a.score.toFixed(2)}</span>}
              </div>
              <div className="p5-card-meta" style={{color:'#71717a',fontSize:'0.7rem'}}>
                {new Date(a.timestamp).toLocaleString()}
              </div>
            </div>
          ))
      }
    </div>
  );

  const renderSuspiciousDNS = () => (
    <div style={{maxHeight:'600px',overflowY:'auto'}}>
      {suspiciousDNS.length === 0
        ? <p style={{color:'#71717a',fontSize:'0.8rem'}}>No suspicious DNS detected</p>
        : suspiciousDNS.map((d, i) => (
            <div key={i} className="p5-card" style={{borderLeft:'4px solid #ef4444'}}>
              <div className="p5-card-row">
                <b>{d.query_name}</b>
                <span className="p5-pill p5-critical">{d.reason || 'SUSPICIOUS'}</span>
              </div>
              <div className="p5-card-meta">
                <span>Source: {d.src_ip}</span>
                <span>Type: {d.query_type}</span>
              </div>
              <div className="p5-card-meta" style={{color:'#71717a',fontSize:'0.7rem'}}>
                {d.entropy !== undefined && <span>Entropy: {d.entropy.toFixed(2)} bits/char  </span>}
                {d.response_code !== undefined && <span>RC: {d.response_code}</span>}
              </div>
              <div className="p5-card-meta" style={{color:'#71717a',fontSize:'0.7rem'}}>
                {new Date(d.timestamp).toLocaleString()}
              </div>
            </div>
          ))
      }
    </div>
  );

  const renderRogueEvents = () => (
    <div style={{maxHeight:'600px',overflowY:'auto'}}>
      {rogueEvents.length === 0
        ? <p style={{color:'#71717a',fontSize:'0.8rem'}}>No rogue AP events</p>
        : rogueEvents.map((r, i) => (
            <div key={i} className="p5-card">
              <div className="p5-card-row">
                <b>{r.ssid || '(hidden)'}</b>
                <span className={`p5-pill ${r.event_type==='deauth'?'p5-critical':'p5-normal'}`}>{r.event_type}</span>
              </div>
              <div className="p5-card-meta">
                <span>BSSID: {r.bssid}</span>
              </div>
              <div className="p5-card-meta" style={{color:'#71717a',fontSize:'0.7rem'}}>
                {r.channel && <span>Ch{r.channel} </span>}
                {r.rssi !== undefined && <span>RSSI: {r.rssi} </span>}
                {new Date(r.timestamp || r.seen_at).toLocaleString()}
              </div>
            </div>
          ))
      }
    </div>
  );

  const TABS = [
    {id:'anomalies', label:`ANOMALIES (${anomalies.length})`},
    {id:'dns', label:`SUSPICIOUS DNS (${suspiciousDNS.length})`},
    {id:'rogue', label:`ROGUE EVENTS (${rogueEvents.length})`},
  ];

  return (
    <div>
      <h3 className="section-title">SECURITY EVENTS</h3>
      <div style={{display:'flex',gap:'0.5rem',marginBottom:'1rem',flexWrap:'wrap'}}>
        {TABS.map(t => (
          <button key={t.id} className={`p5-tab-btn ${tab===t.id?'active':''}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      {loading && <p style={{color:'#71717a',fontSize:'0.8rem'}}>Loading...</p>}
      {!loading && tab === 'anomalies' && renderAnomalies()}
      {!loading && tab === 'dns' && renderSuspiciousDNS()}
      {!loading && tab === 'rogue' && renderRogueEvents()}
    </div>
  );
};

export default SecurityPanel;
