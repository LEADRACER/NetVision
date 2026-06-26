import React, { useState, useEffect } from 'react';

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const SchedulesPanel = () => {
  const [schedules, setSchedules] = useState([]);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('schedules');

  // New schedule form
  const [showForm, setShowForm] = useState(false);
  const [newSched, setNewSched] = useState({ target:'', profile:'deep', interval:'3600', name:'' });

  const fetchData = () => {
    setLoading(true);
    Promise.all([
      fetch(`${API}/scan/schedule`).then(r => r.json()).catch(() => []),
      fetch(`${API}/scan/history`).then(r => r.json()).catch(() => ({tasks:[]})),
    ]).then(([s, h]) => {
      setSchedules(s.schedules || s || []);
      setHistory(h.tasks || []);
      setLoading(false);
    });
  };

  useEffect(() => { fetchData(); const iv = setInterval(fetchData, 10000); return () => clearInterval(iv); }, []);

  const handleCreate = async () => {
    const s = newSched;
    if (!s.target) return;
    try {
      await fetch(`${API}/scan/schedule`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ target:s.target, profile:s.profile, interval:parseInt(s.interval), name:s.name || undefined }),
      });
      setShowForm(false);
      setNewSched({ target:'', profile:'deep', interval:'3600', name:'' });
      fetchData();
    } catch(e) { console.error(e); }
  };

  const handleToggle = async (id) => {
    try {
      await fetch(`${API}/scan/schedule/${id}/toggle`, { method:'POST' });
      fetchData();
    } catch(e) { console.error(e); }
  };

  const handleDelete = async (id) => {
    try {
      await fetch(`${API}/scan/schedule/${id}`, { method:'DELETE' });
      fetchData();
    } catch(e) { console.error(e); }
  };

  if (loading && schedules.length === 0 && history.length === 0) {
    return <p style={{color:'#71717a',fontSize:'0.8rem'}}>Loading...</p>;
  }

  return (
    <div>
      <div style={{display:'flex',gap:'0.5rem',marginBottom:'1.5rem'}}>
        <button className={`p5-tab-btn ${tab==='schedules'?'active':''}`} onClick={() => setTab('schedules')}>SCHEDULES</button>
        <button className={`p5-tab-btn ${tab==='history'?'active':''}`} onClick={() => setTab('history')}>HISTORY</button>
      </div>

      {tab === 'schedules' && (
        <>
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'1rem'}}>
            <h3 className="section-title" style={{marginBottom:0}}>SCAN SCHEDULES</h3>
            <button className="p5-btn-sm" onClick={() => setShowForm(!showForm)}>
              {showForm ? 'CANCEL' : '+ SCHEDULE'}
            </button>
          </div>

          {showForm && (
            <div className="p5-card" style={{marginBottom:'1.5rem'}}>
              <h4 className="stat-label">NEW SCHEDULE</h4>
              <div style={{display:'flex',flexDirection:'column',gap:'0.75rem',marginTop:'0.75rem'}}>
                <input className="p5-input" placeholder="Target IP/range" value={newSched.target} onChange={e => setNewSched({...newSched,target:e.target.value})} />
                <input className="p5-input" placeholder="Schedule name" value={newSched.name} onChange={e => setNewSched({...newSched,name:e.target.value})} />
                <div style={{display:'flex',gap:'0.75rem'}}>
                  <select className="p5-input" style={{flex:1}} value={newSched.profile} onChange={e => setNewSched({...newSched,profile:e.target.value})}>
                    <option value="quick">Quick</option><option value="deep">Deep</option><option value="stealth">Stealth</option>
                    <option value="full">Full</option><option value="vuln">Vuln</option><option value="discovery">Discovery</option>
                  </select>
                  <select className="p5-input" style={{flex:1}} value={newSched.interval} onChange={e => setNewSched({...newSched,interval:e.target.value})}>
                    <option value="300">5 min</option><option value="900">15 min</option><option value="1800">30 min</option>
                    <option value="3600">1 hour</option><option value="21600">6 hours</option><option value="86400">24 hours</option>
                  </select>
                </div>
                <button className="p5-btn-sm p5-btn-green" onClick={handleCreate}>CREATE SCHEDULE</button>
              </div>
            </div>
          )}

          {schedules.length === 0 ? (
            <p style={{color:'#71717a',fontSize:'0.8rem'}}>No schedules configured</p>
          ) : (
            <div style={{display:'flex',flexDirection:'column',gap:'0.75rem'}}>
              {schedules.map((s, i) => (
                <div key={s.id || i} className="p5-card" style={{borderLeft:`4px solid ${s.enabled ? '#22c55e' : '#71717a'}`}}>
                  <div className="p5-card-row">
                    <div>
                      <b>{s.name || s.target}</b>
                      <span className={`p5-pill ${s.enabled?'p5-normal':'p5-low'}`} style={{marginLeft:'0.5rem'}}>{s.enabled?'ON':'OFF'}</span>
                    </div>
                    <div style={{display:'flex',gap:'0.5rem'}}>
                      <button className="p5-btn-xs" onClick={() => handleToggle(s.id)}>{s.enabled ? 'PAUSE' : 'RESUME'}</button>
                      <button className="p5-btn-xs p5-btn-red" onClick={() => handleDelete(s.id)}>DEL</button>
                    </div>
                  </div>
                  <div className="p5-card-meta">
                    <span>Target: {s.target}</span>
                    <span>Profile: {s.profile}</span>
                  </div>
                  <div className="p5-card-meta">
                    <span>Every {s.interval}s</span>
                    {s.created_at && <span>Created: {new Date(s.created_at*1000).toLocaleString()}</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {tab === 'history' && (
        <>
          <h3 className="section-title">SCAN HISTORY</h3>
          {history.length === 0 ? (
            <p style={{color:'#71717a',fontSize:'0.8rem'}}>No scan history</p>
          ) : (
            <div style={{display:'flex',flexDirection:'column',gap:'0.75rem',maxHeight:'500px',overflowY:'auto'}}>
              {history.map((h, i) => (
                <div key={h.id || i} className="p5-card">
                  <div className="p5-card-row">
                    <b>{h.target}</b>
                    <span style={{fontSize:'0.7rem',color:'#71717a'}}>{h.scan_id && `#${h.scan_id}`}</span>
                  </div>
                  <div className="p5-card-meta">
                    <span>Profile: {h.profile}</span>
                    <span>Priority: {h.priority}</span>
                  </div>
                  <div className="p5-card-meta">
                    <span>Started: {h.started_at ? new Date(h.started_at).toLocaleString() : 'N/A'}</span>
                    {h.devices_found !== undefined && <span>Devices: {h.devices_found}</span>}
                  </div>
                  {h.completed_at && (
                    <div className="p5-card-meta">
                      <span>Completed: {new Date(h.completed_at).toLocaleString()}</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default SchedulesPanel;
