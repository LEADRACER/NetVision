import React, { useState, useEffect } from 'react';

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const QueuePanel = () => {
  const [queue, setQueue] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchQueue = () => {
    fetch(`${API}/scan/queue`)
      .then(r => r.json())
      .then(d => { setQueue(d); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { fetchQueue(); const iv = setInterval(fetchQueue, 3000); return () => clearInterval(iv); }, []);

  if (loading) return <p style={{color:'#71717a',fontSize:'0.8rem'}}>Loading queue...</p>;
  if (!queue) return <p style={{color:'#71717a',fontSize:'0.8rem'}}>Could not load queue.</p>;

  const active = queue.active_task;
  const pending = queue.pending_tasks || [];

  return (
    <div>
      <h3 className="section-title">SCAN QUEUE</h3>

      {/* Active Task */}
      <div className="p5-card" style={{borderLeft:'4px solid #22c55e',marginBottom:'1.5rem'}}>
        <p className="stat-label">ACTIVE TASK</p>
        {active ? (
          <div>
            <p><b>Target:</b> {active.target}</p>
            <p><b>Profile:</b> {active.profile}</p>
            <p><b>Priority:</b> <span className={`p5-pill p5-${(active.priority||'').toLowerCase()}`}>{active.priority}</span></p>
            <p><b>Started:</b> {active.created_at}</p>
            <p><b>Scan ID:</b> {active.scan_id}</p>
          </div>
        ) : (
          <p style={{color:'#71717a',fontSize:'0.8rem'}}>No active scan</p>
        )}
      </div>

      <div className="stats-grid" style={{marginBottom:'1.5rem'}}>
        <div className="stat-box">
          <p className="stat-label">ACTIVE</p>
          <b>{queue.is_active ? 'Yes' : 'No'}</b>
        </div>
        <div className="stat-box">
          <p className="stat-label">PENDING</p>
          <b>{queue.pending_count}</b>
        </div>
      </div>

      {/* Pending Tasks */}
      <h4 className="section-title">PENDING TASKS ({pending.length})</h4>
      {pending.length === 0 ? (
        <p style={{color:'#71717a',fontSize:'0.8rem'}}>No pending tasks</p>
      ) : (
        <div style={{display:'flex',flexDirection:'column',gap:'0.75rem'}}>
          {pending.map((t, i) => (
            <div key={i} className="p5-card" style={{borderLeft:`4px solid ${t.priority === 'critical' ? '#ef4444' : t.priority === 'high' ? '#f97316' : t.priority === 'normal' ? '#22c55e' : '#71717a'}`}}>
              <div className="p5-card-row">
                <b>{t.target}</b>
                <span className={`p5-pill p5-${(t.priority||'normal').toLowerCase()}`}>{t.priority}</span>
              </div>
              <div className="p5-card-meta">
                <span>Profile: {t.profile}</span>
                <span>Requester: {t.requester}</span>
              </div>
              <div className="p5-card-meta">
                <span>Queued: {new Date(t.created_at * 1000).toLocaleString()}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default QueuePanel;
