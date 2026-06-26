import React, { useState, useEffect } from 'react';

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const StreamCapturePanel = () => {
  const [status, setStatus] = useState(null);
  const [topTalkers, setTopTalkers] = useState([]);
  const [summary, setSummary] = useState(null);
  const [duration, setDuration] = useState(30);
  const [bpf, setBpf] = useState('');
  const [rogueDuration, setRogueDuration] = useState(10);
  const [rogueResult, setRogueResult] = useState(null);
  const [rogueScanning, setRogueScanning] = useState(false);

  const fetchStatus = () => {
    fetch(`${API}/capture/streaming-status`).then(r=>r.json()).then(setStatus).catch(()=>{});
    fetch(`${API}/capture/top-talkers`).then(r=>r.json()).then(setTopTalkers).catch(()=>{});
    fetch(`${API}/capture/analysis-summary`).then(r=>r.json()).then(setSummary).catch(()=>{});
  };

  useEffect(() => { fetchStatus(); const iv = setInterval(fetchStatus, 5000); return () => clearInterval(iv); }, []);

  const handleStartStream = async () => {
    try {
      const r = await fetch(`${API}/capture/start-streaming`, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({duration, bpf_filter: bpf}),
      });
      if (r.ok) fetchStatus();
    } catch(e) { console.error(e); }
  };

  const handleStopStream = async () => {
    try {
      await fetch(`${API}/capture/stop-streaming`, {method:'POST'});
      fetchStatus();
    } catch(e) { console.error(e); }
  };

  const handleRogueScan = async () => {
    setRogueScanning(true);
    setRogueResult(null);
    try {
      const r = await fetch(`${API}/capture/rogue-scan`, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({duration: rogueDuration}),
      });
      const d = await r.json();
      setRogueResult(d);
    } catch(e) { console.error(e); }
    setRogueScanning(false);
  };

  return (
    <div>
      <h3 className="section-title">STREAMING CAPTURE</h3>

      {/* Status row */}
      <div className="stats-grid" style={{marginBottom:'1.5rem'}}>
        <div className="stat-box">
          <p className="stat-label">STREAMING</p>
          <b style={{color: status?.streaming ? '#22c55e' : '#71717a'}}>{status?.streaming ? 'ACTIVE' : 'IDLE'}</b>
        </div>
        <div className="stat-box">
          <p className="stat-label">SNAPSHOTS</p>
          <b>{summary?.total_snapshots || 0}</b>
        </div>
        <div className="stat-box">
          <p className="stat-label">HTTP</p>
          <b>{summary?.http_requests || 0}</b>
        </div>
        <div className="stat-box">
          <p className="stat-label">DNS</p>
          <b>{summary?.dns_queries || 0}</b>
        </div>
        <div className="stat-box">
          <p className="stat-label">TLS</p>
          <b>{summary?.tls_handshakes || 0}</b>
        </div>
        <div className="stat-box">
          <p className="stat-label">ANOMALIES</p>
          <b>{summary?.anomalies || 0}</b>
        </div>
      </div>

      {/* Controls */}
      <div className="p5-card" style={{marginBottom:'1.5rem'}}>
        <p className="stat-label">STREAM CONTROLS</p>
        <div style={{display:'flex',gap:'0.75rem',marginTop:'0.75rem',flexWrap:'wrap'}}>
          <div style={{flex:1,minWidth:'120px'}}>
            <label style={{fontSize:'0.7rem',color:'#71717a',display:'block',marginBottom:'0.25rem'}}>Duration (s)</label>
            <input className="p5-input" type="number" min="5" max="600" value={duration} onChange={e => setDuration(parseInt(e.target.value)||30)} />
          </div>
          <div style={{flex:2,minWidth:'200px'}}>
            <label style={{fontSize:'0.7rem',color:'#71717a',display:'block',marginBottom:'0.25rem'}}>BPF Filter (optional)</label>
            <input className="p5-input" placeholder="e.g., host 192.168.1.1" value={bpf} onChange={e => setBpf(e.target.value)} />
          </div>
        </div>
        <div style={{display:'flex',gap:'0.75rem',marginTop:'1rem'}}>
          {!status?.streaming ? (
            <button className="p5-btn-sm p5-btn-green" onClick={handleStartStream}>START STREAMING</button>
          ) : (
            <button className="p5-btn-sm p5-btn-red" onClick={handleStopStream}>STOP STREAMING</button>
          )}
        </div>
      </div>

      {/* Top Talkers */}
      <h4 className="section-title">TOP TALKERS</h4>
      {topTalkers.length === 0 ? (
        <p style={{color:'#71717a',fontSize:'0.8rem'}}>No data yet</p>
      ) : (
        <div style={{display:'flex',flexDirection:'column',gap:'0.5rem',marginBottom:'1.5rem'}}>
          {topTalkers.map((t, i) => (
            <div key={i} className="p5-card" style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
              <div>
                <b>{t.ip}</b>
                {t.mac && <span style={{fontSize:'0.7rem',color:'#71717a',marginLeft:'0.5rem'}}>{t.mac}</span>}
              </div>
              <div style={{textAlign:'right',fontSize:'0.75rem'}}>
                <div>{t.total_packets} packets</div>
                <div style={{color:'#71717a'}}>{t.total_bytes ? (t.total_bytes/1024).toFixed(1) : 0} KB</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Rogue AP Scan */}
      <h4 className="section-title">ROGUE AP SCAN</h4>
      <div className="p5-card" style={{marginBottom:'1.5rem'}}>
        <div style={{display:'flex',gap:'0.75rem',alignItems:'flex-end',flexWrap:'wrap'}}>
          <div style={{flex:1,minWidth:'100px'}}>
            <label style={{fontSize:'0.7rem',color:'#71717a',display:'block',marginBottom:'0.25rem'}}>Duration (s)</label>
            <input className="p5-input" type="number" min="5" max="120" value={rogueDuration} onChange={e => setRogueDuration(parseInt(e.target.value)||10)} />
          </div>
          <button className="p5-btn-sm" onClick={handleRogueScan} disabled={rogueScanning}>
            {rogueScanning ? 'SCANNING...' : 'SCAN FOR ROGUE APS'}
          </button>
        </div>
        {rogueResult && (
          <div style={{marginTop:'1rem'}}>
            <div className="stats-grid">
              <div className="stat-box"><p className="stat-label">BEACONS</p><b>{rogueResult.total_beacons}</b></div>
              <div className="stat-box"><p className="stat-label">DEAUTHS</p><b>{rogueResult.total_deauth}</b></div>
              <div className="stat-box"><p className="stat-label">NEW APS</p><b>{(rogueResult.access_points||[]).length}</b></div>
            </div>
            {(rogueResult.access_points||[]).length > 0 && (
              <div style={{marginTop:'0.75rem',display:'flex',flexDirection:'column',gap:'0.5rem'}}>
                {rogueResult.access_points.slice(0,10).map((ap, i) => (
                  <div key={i} className="p5-card-row" style={{fontSize:'0.75rem',borderBottom:'1px solid #e4e4e7',paddingBottom:'0.5rem'}}>
                    <span><b>{ap.ssid || '(hidden)'}</b> {ap.bssid}</span>
                    <span style={{color:'#71717a'}}>Ch{ap.channel} RSSI:{ap.rssi}</span>
                  </div>
                ))}
              </div>
            )}
            {rogueResult.deauth_events && rogueResult.deauth_events.length > 0 && (
              <p style={{fontSize:'0.75rem',color:'#ef4444',marginTop:'0.5rem'}}>
                ⚠ {rogueResult.deauth_events.length} deauth frame{rogueResult.deauth_events.length>1?'s':''} detected
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default StreamCapturePanel;
