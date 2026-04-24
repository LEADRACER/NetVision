import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Search, Activity, Zap, RefreshCw, Wifi, WifiOff } from 'lucide-react';
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
    const [scanDuration, setScanDuration] = useState(null);
    const [scanTarget, setScanTarget] = useState(''); // Custom target input
    const [scanAll, setScanAll] = useState(false); // All subnets flag
    const [connectionStatus, setConnectionStatus] = useState('connected');
    const [lastUpdate, setLastUpdate] = useState(null);
    const [scanProgress, setScanProgress] = useState(0);
    const [currentSubnet, setCurrentSubnet] = useState('');
    const lastUpdateRef = useRef(null);

    // Track scan progress
    useEffect(() => {
        if (isScanning) {
            const interval = setInterval(() => {
                setScanProgress(prev => (prev < 100 ? prev + 2 : 100));
            }, 500);
            return () => clearInterval(interval);
        } else {
            setScanProgress(0);
        }
    }, [isScanning]);

    // Update last update timestamp on device changes
    useEffect(() => {
        lastUpdateRef.current = new Date();
        setLastUpdate(lastUpdateRef.current);
    }, [devices]);

    useEffect(() => {
        let ws;
        let reconnectTimer;

        const connect = () => {
            setConnectionStatus('connecting');
            ws = new WebSocket(WS_URL);
            ws.onopen = () => {
                setConnectionStatus('connected');
            };
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
                } else if (data.type === 'subnet_start') {
                    setCurrentSubnet(data.subnet);
                }
            };
            ws.onclose = () => {
                setConnectionStatus('disconnected');
                reconnectTimer = setTimeout(connect, 5000);
            };
            ws.onerror = () => {
                setConnectionStatus('disconnected');
            };
        };

        connect();

        return () => {
            clearTimeout(reconnectTimer);
            if (ws) ws.close();
        };
    }, []);

    // Keyboard shortcut to close overlay
    useEffect(() => {
        const handleKeyDown = (e) => {
            if (e.key === 'Escape' && selected) {
                setSelected(null);
            }
        };
        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [selected]);

    const runScan = useCallback(() => {
        // API_URL is a stable constant, safe to use without being a dependency
        const url = new URL(`${API_URL}/scan`);
        url.searchParams.set('profile', 'deep');
        if (scanDuration) {
            url.searchParams.set('duration', scanDuration);
        }
        const target = scanAll ? 'all' : scanTarget.trim();
        if (target) {
            url.searchParams.set('target', target);
        }
        fetch(url.toString());
        setIsScanning(true);
        setCurrentSubnet('');
    }, [scanDuration, scanTarget, scanAll]); // API_URL omitted — constant // API_URL is stable constant, okay to include

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

    const formatTime = (date) => {
        if (!date) return 'Never';
        return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    };

    const totalOpenPorts = devices.reduce((acc, d) => acc + d.ports.filter(p => p.state === 'open').length, 0);
    const vulnCount = devices.filter(d => d.vulns_detected).length;

    return (
        <div className="app-container">
            {/* Sidebar */}
            <div className="sidebar">
                {/* Sticky header with stats */}
                <div className="sidebar-sticky">
                    <div className="sidebar-sticky-header">
                        <div className="sidebar-header">
                            <h1>NETVISION</h1>
                            <p>NEUTRAL DISCOVERY v4.2</p>
                        </div>
                        <div className="sidebar-sticky-actions">
                            <button
                                className="btn-refresh"
                                onClick={() => window.location.reload()}
                                title="Refresh page"
                            >
                                <RefreshCw size={12} />
                                Refresh
                            </button>
                        </div>
                    </div>

                    <div className="sidebar-stats">
                        <div className="stat-item">
                            <span className="stat-value">{devices.length}</span>
                            <span className="stat-label-sm">NODES</span>
                        </div>
                        <div className="stat-item">
                            <span className="stat-value">{totalOpenPorts}</span>
                            <span className="stat-label-sm">OPEN PORTS</span>
                        </div>
                    </div>

                    <div className="connection-status">
                        {connectionStatus === 'connected' ? <Wifi size={12} /> : <WifiOff size={12} />}
                        <span>{connectionStatus === 'connected' ? 'Connected' : connectionStatus === 'connecting' ? 'Connecting...' : 'Disconnected'}</span>
                    </div>
                </div>

                {/* Scan button with progress */}
                <div>
                    {/* Target input */}
                    <div style={{marginBottom: '0.75rem'}}>
                        <div style={{display: 'flex', gap: '0.5rem', marginBottom: '0.5rem'}}>
                            <button
                                type="button"
                                onClick={() => { setScanAll(true); setScanTarget(''); }}
                                style={{
                                    flex: 1,
                                    padding: '0.5rem',
                                    borderRadius: '6px',
                                    border: scanAll ? '1px solid var(--accent-green)' : '1px solid #71717a',
                                    background: scanAll ? 'rgba(34, 197, 94, 0.1)' : 'transparent',
                                    color: scanAll ? 'var(--accent-green)' : '#d4d4d8',
                                    fontSize: '0.7rem',
                                    fontWeight: 700,
                                    cursor: 'pointer',
                                    transition: 'all 0.2s'
                                }}
                            >
                                ALL SUBNETS
                            </button>
                        </div>
                        <input
                            type="text"
                            placeholder={scanAll ? "Scanning all private subnets..." : "e.g., 192.168.1.0/24 or 192.168.1.1"}
                            value={scanTarget}
                            onChange={(e) => { setScanTarget(e.target.value); setScanAll(false); }}
                            disabled={isScanning}
                            style={{
                                width: '100%',
                                padding: '0.625rem 0.75rem',
                                borderRadius: '8px',
                                border: '1px solid #71717a',
                                background: isScanning ? '#3f3f46' : '#52525b',
                                color: '#fff',
                                fontSize: '0.75rem',
                                fontFamily: 'Inter, sans-serif',
                                outline: 'none',
                                transition: 'border-color 0.2s'
                            }}
                        />
                    </div>

                    {/* Duration selector */}
                    <div style={{marginBottom: '0.75rem'}}>
                        <select
                            value={scanDuration || ''}
                            onChange={(e) => setScanDuration(e.target.value ? parseInt(e.target.value) : null)}
                            disabled={isScanning}
                            style={{
                                width: '100%',
                                padding: '0.625rem 0.75rem',
                                borderRadius: '8px',
                                border: '1px solid #71717a',
                                background: isScanning ? '#3f3f46' : '#52525b',
                                color: '#fff',
                                fontSize: '0.75rem',
                                fontFamily: 'Inter, sans-serif',
                                cursor: 'pointer',
                                outline: 'none'
                            }}
                        >
                            <option value="" style={{background: '#52525b', color: '#fff'}}>Duration: Unlimited</option>
                            <option value="30" style={{background: '#52525b', color: '#fff'}}>30 seconds</option>
                            <option value="60" style={{background: '#52525b', color: '#fff'}}>1 minute</option>
                        </select>
                    </div>

                    <button className="btn-scan" onClick={runScan} disabled={isScanning}>
                        {isScanning ? <Activity size={18} className="spin" /> : <Search size={18} />}
                        {isScanning ? 'SCANNING...' : 'EXECUTE SCAN'}
                    </button>

                    {isScanning && (
                        <div className="scan-progress-bar">
                            <div className="scan-progress-fill" style={{width: `${scanProgress}%`}} />
                        </div>
                    )}

                    {/* Current subnet indicator */}
                    {isScanning && currentSubnet && (
                        <div style={{
                            marginTop: '0.75rem',
                            fontSize: '0.65rem',
                            color: '#d4d4d8',
                            textAlign: 'center',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: '0.5rem'
                        }}>
                            <Wifi size={10} />
                            <span>{currentSubnet}</span>
                        </div>
                    )}
                </div>

                {/* Devices list */}
                <div className="devices-list">
                    <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                        <p className="devices-count">NODES ({devices.length})</p>
                        {vulnCount > 0 && (
                            <span style={{fontSize: '0.6rem', color: '#ef4444', fontWeight: 700}}>
                                {vulnCount} ⚠
                            </span>
                        )}
                    </div>
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
                            <p style={{fontSize: '0.6rem', marginTop: '0.5rem'}}>Click "Execute Scan" to begin</p>
                        </div>
                    )}
                </div>

                {/* Last update */}
                {lastUpdate && (
                    <div className="last-update">
                        Last update: {formatTime(lastUpdate)}
                    </div>
                )}
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
                            <Wifi size={64} style={{marginBottom: '1rem', opacity: 0.3}} />
                            <h2 style={{fontWeight: 300, color: '#71717a'}}>Passive Monitor Online</h2>
                            <p style={{fontSize: '0.8rem', color: '#a1a1aa', marginTop: '0.5rem'}}>Waiting for scan results...</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Details Overlay with backdrop */}
            {selected && (
                <>
                    <div className="overlay-backdrop" onClick={() => setSelected(null)} />
                    <div className="details-overlay">
                        <div className="details-header">
                            <div>
                                <h2>{selected.ip}</h2>
                                <p>{selected.vendor}</p>
                            </div>
                            <button className="details-close" onClick={() => setSelected(null)} title="Close (ESC)">✕</button>
                        </div>

                        <div className="details-body">
                            <div className="stats-grid">
                                <div className="stat-box">
                                    <p className="stat-label">OS</p>
                                    <b title={selected.os}>{selected.os || 'Unknown'}</b>
                                </div>
                                <div className="stat-box">
                                    <p className="stat-label">LATENCY</p>
                                    <b>{selected.latency_ms ? selected.latency_ms.toFixed(2) : "0.00"} ms</b>
                                </div>
                                <div className="stat-box">
                                    <p className="stat-label">DISTANCE</p>
                                    <b>{selected.distance || 1} hop{selected.distance !== 1 ? 's' : ''}</b>
                                </div>
                                <div className="stat-box">
                                    <p className="stat-label">ACTIVE PORTS</p>
                                    <b>{selected.ports.filter(p => p.state === 'open').length}</b>
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

                                {isCapturing && (
                                    <div className="scan-overlay">
                                        <div className="scan-overlay-content">
                                            <div className="scan-overlay-spinner" />
                                            <p className="scan-overlay-text">Capturing packets...</p>
                                        </div>
                                    </div>
                                )}

                                {captureResult && !isCapturing && (
                                    <div className="capture-result">
                                        <div className="result-row">
                                            <div>
                                                <span>Total Packets: </span>
                                                <b style={{color: '#22c55e'}}>{captureResult.total_packets}</b>
                                            </div>
                                            <div style={{fontSize: '0.75rem', color: '#71717a'}}>
                                                {captureResult.total_bytes.toLocaleString()} bytes
                                            </div>
                                        </div>
                                        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem'}}>
                                            <span style={{fontSize: '0.8rem'}}>Protocol Distribution:</span>
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
                                            {Object.entries(captureResult.protocols || {}).map(([proto, count]) => {
                                                const percentage = Math.round((count / (captureResult.total_packets || 1)) * 100);
                                                return (
                                                    <span key={proto} className="protocol-tag" title={`${percentage}% of traffic`}>
                                                        <strong>{proto}</strong>: {count}
                                                    </span>
                                                );
                                            })}
                                        </div>
                                    </div>
                                )}
                            </div>

                            <h4 className="section-title">SERVICES ({selected.ports.length})</h4>
                            <div className="services-list">
                                {selected.ports.map(p => {
                                    const isOpen = p.state === 'open';
                                    return (
                                        <div
                                            key={`${p.port}-${p.protocol}`}
                                            className="service-item"
                                            style={{borderLeftColor: isOpen ? 'var(--accent-green)' : '#71717a'}}
                                        >
                                            <div>
                                                <b>{p.port}/{p.protocol}</b>
                                                <div style={{fontSize: '0.8rem', color: '#71717a'}}>
                                                    {p.service || 'unknown'}
                                                    {p.version && ` ${p.version}`}
                                                </div>
                                            </div>
                                            <span className={`port-tag ${isOpen ? 'important' : ''}`} style={{alignSelf: 'center'}}>
                                                {p.state}
                                            </span>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </>
            )}
        </div>
    );
};

export default App;
