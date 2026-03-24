import React, { useState, useEffect } from 'react';
import { Search, Monitor, Activity, Shield, ShieldAlert, Wifi, Zap } from 'lucide-react';

const WS_URL = "ws://localhost:8000/ws";
const API_URL = "http://localhost:8000";

const App = () => {
    const [devices, setDevices] = useState([]);
    const [isScanning, setIsScanning] = useState(false);
    const [selected, setSelected] = useState(null);
    const [isCapturing, setIsCapturing] = useState(false);
    const [captureResult, setCaptureResult] = useState(null);
    const [captureDuration, setCaptureDuration] = useState(10);

    useEffect(() => {
        let ws = new WebSocket(WS_URL);
        ws.onmessage = (e) => {
            const data = JSON.parse(e.data);
            if (data.type === 'update') {
                setDevices(prev => {
                    const next = [...prev];
                    data.devices.forEach(d => {
                        const i = next.findIndex(x => x.ip === d.ip);
                        if (i > -1) next[i] = d; else next.push(d);
                    });
                    return next;
                });
                setIsScanning(data.is_scanning);
            } else if (data.type === 'status') {
                setIsScanning(data.is_scanning);
                if (data.devices) setDevices(data.devices);
            }
        };
        ws.onclose = () => setTimeout(() => { ws = new WebSocket(WS_URL); }, 5000);
        return () => ws.close();
    }, []);

    const runScan = () => {
        fetch(`${API_URL}/scan?profile=deep`);
        setIsScanning(true);
    };

    const handleCapture = async (ip) => {
        setIsCapturing(true);
        setCaptureResult(null);
        try {
            const resp = await fetch(`${API_URL}/capture`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, duration: captureDuration })
            });
            const data = await resp.json();
            setCaptureResult(data);
        } catch (err) {
            console.error("Capture failed", err);
        } finally {
            setIsCapturing(false);
        }
    };

    return (
        <div className="app-container">
            {/* Neutral Grey Sidebar */}
            <div className="sidebar">
                <div style={{marginBottom: '2rem'}}>
                    <h1 style={{fontFamily: 'Space Grotesk', fontSize: '1.8rem', letterSpacing: '-1px', color: '#fff'}}>NETVISION</h1>
                    <p style={{color: '#d4d4d8', fontSize: '0.7rem', fontWeight: 600}}>NEUTRAL DISCOVERY v4.2</p>
                </div>

                <button className="btn-scan" onClick={runScan} disabled={isScanning}>
                    {isScanning ? <Activity size={18} className="spin" /> : <Search size={18} />}
                    {isScanning ? 'SCANNING...' : 'EXECUTE SCAN'}
                </button>

                <div style={{overflowY: 'auto', flex: 1}}>
                    <p style={{fontSize: '0.7rem', color: '#d4d4d8', fontWeight: 800, marginBottom: '1rem'}}>NODES ({devices.length})</p>
                    {devices.map(d => (
                        <div key={d.ip} onClick={() => setSelected(d)} className="device-card" style={{
                            background: selected?.ip === d.ip ? '#71717a' : '#52525b',
                            borderColor: selected?.ip === d.ip ? '#a1a1aa' : '#71717a'
                        }}>
                            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                                <span style={{fontWeight: 700, fontSize: '0.9rem', color: '#fff'}}>{d.ip}</span>
                                <div className={`status-indicator ${d.vulns_detected ? 'status-red' : 'status-green'}`} />
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Dotted Map Area */}
            <div className="main-map" style={{padding: '2rem', overflowY: 'auto'}}>
                <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1.5rem'}}>
                    {devices.map(d => (
                        <div key={d.ip} onClick={() => setSelected(d)} style={{
                            background: '#fff', border: '1px solid #e4e4e7', borderRadius: 12, padding: '1.5rem',
                            cursor: 'pointer', transition: 'all 0.2s', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)'
                        }}>
                            <div style={{display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem'}}>
                                <div style={{padding: '0.8rem', background: d.vulns_detected ? '#fee2e2' : '#f0fdf4', borderRadius: 12}}>
                                    {d.vulns_detected ? <ShieldAlert size={24} color="#ef4444" /> : <Shield size={24} color="#22c55e" />}
                                </div>
                                <div>
                                    <h3 style={{margin: 0, fontSize: '1.1rem', color: '#18181b'}}>{d.ip}</h3>
                                    <p style={{margin: 0, fontSize: '0.75rem', color: '#71717a'}}>{d.vendor}</p>
                                </div>
                            </div>
                            <div style={{display: 'flex', gap: '0.4rem', flexWrap: 'wrap'}}>
                                {d.ports.slice(0, 3).map(p => (
                                    <span key={p.port} style={{fontSize: '0.6rem', border: '1px solid #e4e4e7', padding: '0.1rem 0.4rem', borderRadius: 4, color: '#52525b'}}>
                                        {p.port}
                                    </span>
                                ))}
                            </div>
                        </div>
                    ))}
                    {devices.length === 0 && (
                        <div style={{gridColumn: '1/-1', textAlign: 'center', padding: '10rem 0', opacity: 0.2}}>
                            <Wifi size={64} style={{marginBottom: '1rem'}} />
                            <h2>Passive Monitor Online</h2>
                        </div>
                    )}
                </div>
            </div>

            {/* Details Overlay */}
            {selected && (
                <div style={{
                    position: 'fixed', top: 0, right: 0, bottom: 0, width: 450, background: '#fff',
                    boxShadow: '-20px 0 50px rgba(0,0,0,0.05)', borderLeft: '1px solid #e4e4e7',
                    display: 'flex', flexDirection: 'column', zIndex: 1000
                }}>
                    <div style={{padding: '2rem', background: '#3f3f46', color: '#fff', display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                        <div>
                            <h2 style={{margin: 0}}>{selected.ip}</h2>
                            <p style={{margin: 0, color: '#d4d4d8', fontSize: '0.8rem'}}>{selected.vendor}</p>
                        </div>
                        <button onClick={() => setSelected(null)} style={{background: 'rgba(255,255,255,0.1)', border: 'none', color: '#fff', padding: '0.5rem', borderRadius: 8, cursor: 'pointer'}}>✕</button>
                    </div>

                    <div style={{padding: '2rem', flex: 1, overflowY: 'auto'}}>
                        <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '1.5rem'}}>
                            <div style={{background: '#f4f4f5', padding: '1rem', borderRadius: 12}}>
                                <p style={{fontSize: '0.7rem', color: '#71717a', fontWeight: 800, marginBottom: '0.5rem'}}>OS</p>
                                <b>{selected.os || 'Unknown'}</b>
                            </div>
                            <div style={{background: '#f4f4f5', padding: '1rem', borderRadius: 12}}>
                                <p style={{fontSize: '0.7rem', color: '#71717a', fontWeight: 800, marginBottom: '0.5rem'}}>LATENCY</p>
                                <b>{selected.latency_ms ? selected.latency_ms.toFixed(2) : "0.00"} ms</b>
                            </div>
                        </div>

                        {/* Capture Engine Section */}
                        <div style={{background: '#fafafa', border: '1px dashed #d1d5db', padding: '1.5rem', borderRadius: 16, marginBottom: '2rem'}}>
                            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem'}}>
                                <h4 style={{margin: 0, fontSize: '0.9rem', color: '#18181b'}}>PACKET CAPTURE ENGINE</h4>
                                <Zap size={16} color={isCapturing ? '#eab308' : '#71717a'} />
                            </div>
                            
                            <div style={{display: 'flex', gap: '0.5rem', marginBottom: '1rem'}}>
                                <input 
                                    type="range" min="5" max="60" value={captureDuration} 
                                    onChange={(e) => setCaptureDuration(parseInt(e.target.value))}
                                    style={{flex: 1, accentColor: '#3f3f46'}}
                                />
                                <span style={{fontSize: '0.8rem', fontWeight: 800, minWidth: '40px'}}>{captureDuration}s</span>
                            </div>

                            <button 
                                onClick={() => handleCapture(selected.ip)} 
                                disabled={isCapturing}
                                style={{
                                    width: '100%', padding: '0.8rem', borderRadius: 8, border: 'none',
                                    background: isCapturing ? '#f4f4f5' : '#18181b', color: '#fff',
                                    fontWeight: 700, cursor: 'pointer', transition: 'all 0.2s'
                                }}
                            >
                                {isCapturing ? 'CAPTURING TRAFFIC...' : 'START TSHARK CAPTURE'}
                            </button>

                            {captureResult && !isCapturing && (
                                <div style={{marginTop: '1rem', borderTop: '1px solid #e5e7eb', paddingTop: '1rem'}}>
                                    <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem'}}>
                                        <div style={{fontSize: '0.8rem'}}>
                                            <span>Total Packets: </span>
                                            <b style={{color: '#22c55e'}}>{captureResult.total_packets}</b>
                                        </div>
                                        <a 
                                            href={`${API_URL}/captures/${captureResult.filename}`} 
                                            download 
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            style={{
                                                fontSize: '0.75rem', color: '#fff', background: '#3f3f46', 
                                                padding: '0.4rem 0.8rem', borderRadius: 6, textDecoration: 'none',
                                                fontWeight: 700
                                            }}
                                        >
                                            DOWNLOAD PCAP
                                        </a>
                                    </div>
                                    <div style={{display: 'flex', flexWrap: 'wrap', gap: '0.4rem'}}>
                                        {Object.entries(captureResult.protocols || {}).map(([proto, count]) => (
                                            <span key={proto} style={{fontSize: '0.65rem', background: '#f1f1f1', padding: '0.2rem 0.5rem', borderRadius: 4}}>
                                                {proto}: {count}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>

                        <h4>SERVICES</h4>
                        {selected.ports.map(p => (
                            <div key={p.port} style={{padding: '1rem', background: '#f4f4f5', border: '1px solid #e4e4e7', borderRadius: 12, borderLeft: '4px solid #22c55e', marginBottom: '0.8rem'}}>
                                <div style={{display: 'flex', justifyContent: 'space-between'}}>
                                    <b>{p.port}/{p.protocol}</b>
                                    <span style={{fontSize: '0.8rem', color: '#71717a'}}>{p.service}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default App;
