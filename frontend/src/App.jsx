import React, { useState, useEffect, useCallback } from 'react';
import { Search, Activity, Zap } from 'lucide-react';
import SidebarDeviceCard from './components/SidebarDeviceCard';
import GridDeviceCard from './components/GridDeviceCard';

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WS_URL = API_URL.replace(/^http/, 'ws') + "/ws";

const App = () => {
    const [devices, setDevices] = useState([]);
    const [isScanning, setIsScanning] = useState(false);
    const [selected, setSelected] = useState(null);
    const [isCapturing, setIsCapturing] = useState(false);
    const [captureResult, setCaptureResult] = useState(null);
    const [captureDuration, setCaptureDuration] = useState(10);

    useEffect(() => {
        let ws;
        let reconnectTimer;

        const connect = () => {
            ws = new WebSocket(WS_URL);
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
            ws.onclose = () => {
                reconnectTimer = setTimeout(connect, 5000);
            };
        };

        connect();

        return () => {
            clearTimeout(reconnectTimer);
            if (ws) ws.close();
        };
    }, []);

    const runScan = useCallback(() => {
        fetch(`${API_URL}/scan?profile=deep`);
        setIsScanning(true);
    }, []);

    const handleSelect = useCallback((device) => {
        setSelected(device);
    }, []);

    const handleCapture = useCallback(async (ip) => {
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
    }, [captureDuration]);

    return (
        <div className="app-container">
            {/* Sidebar */}
            <div className="sidebar">
                <div className="sidebar-header">
                    <h1>NETVISION</h1>
                    <p>NEUTRAL DISCOVERY v4.2</p>
                </div>

                <button className="btn-scan" onClick={runScan} disabled={isScanning}>
                    {isScanning ? <Activity size={18} className="spin" /> : <Search size={18} />}
                    {isScanning ? 'SCANNING...' : 'EXECUTE SCAN'}
                </button>

                <div className="devices-list">
                    <p className="devices-count">NODES ({devices.length})</p>
                    {devices.map(d => (
                        <SidebarDeviceCard
                            key={d.ip}
                            device={d}
                            isSelected={selected?.ip === d.ip}
                            onClick={handleSelect}
                        />
                    ))}
                    {devices.length === 0 && !isScanning && (
                        <div className="empty-state">
                            <p>No devices detected</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Main Map Area */}
            <div className="main-map">
                <div className="device-grid">
                    {devices.map(d => (
                        <GridDeviceCard
                            key={d.ip}
                            device={d}
                            onClick={handleSelect}
                        />
                    ))}
                    {devices.length === 0 && !isScanning && (
                        <div className="empty-state-large">
                            <p>Passive Monitor Online</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Details Overlay */}
            {selected && (
                <div className="details-overlay">
                    <div className="details-header">
                        <div>
                            <h2>{selected.ip}</h2>
                            <p>{selected.vendor}</p>
                        </div>
                        <button className="details-close" onClick={() => setSelected(null)}>✕</button>
                    </div>

                    <div className="details-body">
                        <div className="stats-grid">
                            <div className="stat-box">
                                <p className="stat-label">OS</p>
                                <b>{selected.os || 'Unknown'}</b>
                            </div>
                            <div className="stat-box">
                                <p className="stat-label">LATENCY</p>
                                <b>{selected.latency_ms ? selected.latency_ms.toFixed(2) : "0.00"} ms</b>
                            </div>
                        </div>

                        <div className="capture-section">
                            <div className="capture-header">
                                <h4 className="section-title">PACKET CAPTURE ENGINE</h4>
                                <Zap size={16} color={isCapturing ? '#eab308' : '#71717a'} />
                            </div>

                            <div className="capture-controls">
                                <input
                                    type="range"
                                    min="5"
                                    max="60"
                                    value={captureDuration}
                                    onChange={(e) => setCaptureDuration(parseInt(e.target.value))}
                                    className="capture-slider"
                                />
                                <span className="capture-duration">{captureDuration}s</span>
                            </div>

                            <button
                                onClick={() => handleCapture(selected.ip)}
                                disabled={isCapturing}
                                className="capture-btn"
                            >
                                {isCapturing ? 'CAPTURING TRAFFIC...' : 'START TSHARK CAPTURE'}
                            </button>

                            {captureResult && !isCapturing && (
                                <div className="capture-result">
                                    <div className="result-row">
                                        <div>
                                            <span>Total Packets: </span>
                                            <b style={{color: '#22c55e'}}>{captureResult.total_packets}</b>
                                        </div>
                                        <a
                                            href={`${API_URL}/captures/${captureResult.filename}`}
                                            download
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="result-download"
                                        >
                                            DOWNLOAD PCAP
                                        </a>
                                    </div>
                                    <div className="protocol-tags">
                                        {Object.entries(captureResult.protocols || {}).map(([proto, count]) => (
                                            <span key={proto} className="protocol-tag">
                                                {proto}: {count}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>

                        <h4 className="section-title">SERVICES</h4>
                        <div className="services-list">
                            {selected.ports.map(p => (
                                <div key={p.port} className="service-item">
                                    <div>
                                        <b>{p.port}/{p.protocol}</b>
                                        <div style={{fontSize: '0.8rem', color: '#71717a'}}>{p.service}</div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default App;
