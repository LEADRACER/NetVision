import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Search, Activity, Zap, RefreshCw, Wifi, WifiOff, BarChart3, FileText, Shield, Globe, Network, Scan } from 'lucide-react';
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
    const [scanProfile, setScanProfile] = useState('deep');
    const [scanDuration, setScanDuration] = useState(null);
    const [scanTarget, setScanTarget] = useState('');
    const [scanAll, setScanAll] = useState(false);
    const [traceHops, setTraceHops] = useState(false);
    const [connectionStatus, setConnectionStatus] = useState('connected');
    const [lastUpdate, setLastUpdate] = useState(null);
    const [scanProgress, setScanProgress] = useState(0);
    const [currentSubnet, setCurrentSubnet] = useState('');
    const lastUpdateRef = useRef(null);

    // Reports state
    const [reports, setReports] = useState([]);
    const [generatingReport, setGeneratingReport] = useState(false);

    // Vulnerabilities state
    const [vulnerabilities, setVulnerabilities] = useState([]);

    // Geolocation state
    const [geoData, setGeoData] = useState(null);
    const [loadingGeo, setLoadingGeo] = useState(false);

    // Health history state
    const [healthHistory, setHealthHistory] = useState([]);
    const [healthHours, setHealthHours] = useState(24);

    // Correlation stats state
    const [correlationData, setCorrelationData] = useState(null);

    // Topology state
    const [showTopology, setShowTopology] = useState(false);
    const [topologyData, setTopologyData] = useState(null);

    // Manual probes state
    const [probePorts, setProbePorts] = useState('');
    const [probeResults, setProbeResults] = useState(null);
    const [probing, setProbing] = useState(false);

    // Details overlay tabs
    const [activeTab, setActiveTab] = useState('info');

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
        const url = new URL(`${API_URL}/scan`);
        url.searchParams.set('profile', scanProfile);
        if (scanDuration) {
            url.searchParams.set('duration', scanDuration);
        }
        if (traceHops) {
            url.searchParams.set('trace_hops', 'true');
        }
        const target = scanAll ? 'all' : scanTarget.trim();
        if (target) {
            url.searchParams.set('target', target);
        }
        fetch(url.toString());
        setIsScanning(true);
        setCurrentSubnet('');
    }, [scanProfile, scanDuration, scanTarget, scanAll, traceHops]);

    const stopScan = useCallback(() => {
        fetch(`${API_URL}/scan/stop`);
        setIsScanning(false);
        setScanProgress(0);
    }, [API_URL]);

    const handleSelect = useCallback((device) => {
        setSelected(device);
        setActiveTab('info');
    }, []);

    // Fetch reports list
    useEffect(() => {
        fetch(`${API_URL}/reports`).then(r => r.json()).then(d => setReports(d.reports || [])).catch(() => {});
    }, []);

    // Fetch vulnerabilities when selected device changes
    useEffect(() => {
        if (!selected) {
            setVulnerabilities([]);
            return;
        }
        const url = new URL(`${API_URL}/vulnerabilities`);
        url.searchParams.set('device_ip', selected.ip);
        fetch(url.toString()).then(r => r.json()).then(d => setVulnerabilities(d.vulnerabilities || [])).catch(() => {});
    }, [selected]);

    // Fetch geolocation when selected device changes
    useEffect(() => {
        if (!selected) {
            setGeoData(null);
            return;
        }
        setLoadingGeo(true);
        fetch(`${API_URL}/geolocation/${selected.ip}`).then(r => r.json()).then(d => {
            setGeoData(d);
            setLoadingGeo(false);
        }).catch(() => setLoadingGeo(false));
    }, [selected]);

    // Fetch health history when selected device changes
    useEffect(() => {
        if (!selected) {
            setHealthHistory([]);
            return;
        }
        const url = new URL(`${API_URL}/health/history`);
        url.searchParams.set('device_ip', selected.ip);
        url.searchParams.set('hours', healthHours);
        fetch(url.toString()).then(r => r.json()).then(d => setHealthHistory(d.history || [])).catch(() => {});
    }, [selected, healthHours]);

    // Fetch correlation data on mount
    useEffect(() => {
        fetch(`${API_URL}/correlation`).then(r => r.json()).then(d => setCorrelationData(d)).catch(() => {});
    }, []);

    // Fetch topology data
    useEffect(() => {
        if (!showTopology) return;
        fetch(`${API_URL}/topology`).then(r => r.json()).then(d => setTopologyData(d)).catch(() => {});
    }, [showTopology]);

    const handleGenerateReport = useCallback(async (format) => {
        setGeneratingReport(true);
        try {
            const url = new URL(`${API_URL}/reports/generate`);
            url.searchParams.set('format', format);
            await fetch(url.toString());
            const r = await fetch(`${API_URL}/reports`);
            const d = await r.json();
            setReports(d.reports || []);
        } catch (err) {
            console.error("Report generation failed", err);
        } finally {
            setGeneratingReport(false);
        }
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

    const handleManualProbe = useCallback(async () => {
        if (!selected || !probePorts.trim()) return;
        setProbing(true);
        setProbeResults(null);
        try {
            const url = new URL(`${API_URL}/probes/scan/${selected.ip}`);
            url.searchParams.set('ports', probePorts);
            const resp = await fetch(url.toString());
            const data = await resp.json();
            setProbeResults(data);
        } catch (err) {
            console.error("Probe failed", err);
        } finally {
            setProbing(false);
        }
    }, [selected, probePorts]);

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

                    {/* Trace hops toggle */}
                    <div style={{marginBottom: '0.75rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem'}}>
                        <label style={{fontSize: '0.7rem', color: '#d4d4d8', fontWeight: 600}}>TRACE HOPS</label>
                        <button
                            type="button"
                            onClick={() => setTraceHops(!traceHops)}
                            style={{
                                flexShrink: 0,
                                width: '44px',
                                height: '24px',
                                borderRadius: '12px',
                                border: 'none',
                                background: traceHops ? 'var(--accent-green)' : '#52525b',
                                cursor: 'pointer',
                                position: 'relative',
                                transition: 'background 0.2s',
                                padding: 0
                            }}
                        >
                            <span style={{
                                position: 'absolute',
                                left: traceHops ? '24px' : '2px',
                                top: '2px',
                                width: '20px',
                                height: '20px',
                                borderRadius: '50%',
                                background: '#fff',
                                transition: 'left 0.2s',
                                display: 'block'
                            }} />
                        </button>
                    </div>

                    {/* Profile selector */}
                    <div style={{marginBottom: '0.75rem'}}>
                        <select
                            value={scanProfile}
                            onChange={(e) => setScanProfile(e.target.value)}
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
                            <option value="quick" style={{background: '#52525b', color: '#fff'}}>Quick Scan</option>
                            <option value="deep" style={{background: '#52525b', color: '#fff'}}>Deep Scan</option>
                            <option value="security" style={{background: '#52525b', color: '#fff'}}>Security Scan</option>
                        </select>
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
                        <button
                            onClick={stopScan}
                            style={{
                                width: '100%',
                                padding: '0.75rem',
                                borderRadius: '10px',
                                border: 'none',
                                background: '#ef4444',
                                color: '#fff',
                                fontWeight: 700,
                                fontSize: '0.75rem',
                                cursor: 'pointer',
                                marginTop: '0.5rem',
                                transition: 'all 0.2s',
                                fontFamily: 'Space Grotesk, sans-serif'
                            }}
                        >
                            STOP SCAN
                        </button>
                    )}

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

                    {/* Reports Section */}
                    <div style={{marginTop: '1.5rem', borderTop: '1px solid rgba(255,255,255,0.1)', paddingTop: '1rem'}}>
                        <h4 style={{fontSize: '0.7rem', color: '#d4d4d8', fontWeight: 800, marginBottom: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.5px', display: 'flex', alignItems: 'center', gap: '0.5rem'}}>
                            <FileText size={14} /> REPORTS
                        </h4>
                        <div style={{display: 'flex', gap: '0.4rem', marginBottom: '0.75rem'}}>
                            {['html', 'pdf', 'json', 'csv'].map(fmt => (
                                <button
                                    key={fmt}
                                    onClick={() => handleGenerateReport(fmt)}
                                    disabled={generatingReport}
                                    style={{
                                        flex: 1,
                                        padding: '0.4rem',
                                        borderRadius: '6px',
                                        border: '1px solid #71717a',
                                        background: 'transparent',
                                        color: '#d4d4d8',
                                        fontSize: '0.6rem',
                                        fontWeight: 700,
                                        cursor: 'pointer',
                                        transition: 'all 0.2s',
                                        textTransform: 'uppercase'
                                    }}
                                    onMouseEnter={e => {
                                        e.currentTarget.style.background = 'rgba(255,255,255,0.1)';
                                        e.currentTarget.style.borderColor = 'var(--accent-green)';
                                        e.currentTarget.style.color = '#fff';
                                    }}
                                    onMouseLeave={e => {
                                        e.currentTarget.style.background = 'transparent';
                                        e.currentTarget.style.borderColor = '#71717a';
                                        e.currentTarget.style.color = '#d4d4d8';
                                    }}
                                >
                                    {fmt.toUpperCase()}
                                </button>
                            ))}
                        </div>
                        {reports.length > 0 && (
                            <div style={{maxHeight: '120px', overflowY: 'auto'}}>
                                {reports.map((r, idx) => (
                                    <a
                                        key={idx}
                                        href={`${API_URL}/reports/download/${r.filename}`}
                                        download
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        style={{
                                            display: 'flex',
                                            justifyContent: 'space-between',
                                            alignItems: 'center',
                                            padding: '0.5rem 0.75rem',
                                            background: 'rgba(255,255,255,0.05)',
                                            borderRadius: '6px',
                                            marginBottom: '0.4rem',
                                            fontSize: '0.7rem',
                                            color: '#d4d4d8',
                                            textDecoration: 'none',
                                            transition: 'background 0.2s'
                                        }}
                                        onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.1)'}
                                        onMouseLeave={e => e.currentTarget.style.background = 'rgba(255,255,255,0.05)'}
                                    >
                                        <span style={{overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>{r.filename}</span>
                                        <span style={{fontSize: '0.6rem', color: '#71717a'}}>↓</span>
                                    </a>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Network Stats Section */}
                    {correlationData && (
                        <div style={{marginTop: '1.5rem', borderTop: '1px solid rgba(255,255,255,0.1)', paddingTop: '1rem'}}>
                            <h4 style={{fontSize: '0.7rem', color: '#d4d4d8', fontWeight: 800, marginBottom: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.5px', display: 'flex', alignItems: 'center', gap: '0.5rem'}}>
                                <BarChart3 size={14} /> NETWORK STATS
                            </h4>
                            <div style={{fontSize: '0.65rem', color: '#a1a1aa'}}>
                                {correlationData.vendors && correlationData.vendors.length > 0 && (
                                    <div style={{marginBottom: '0.5rem'}}>
                                        <p style={{color: '#d4d4d8', fontWeight: 600, marginBottom: '0.25rem'}}>VENDORS</p>
                                        {correlationData.vendors.slice(0, 4).map((v, i) => (
                                            <div key={i} style={{display: 'flex', justifyContent: 'space-between', padding: '0.2rem 0'}}>
                                                <span>{v.vendor || 'Unknown'}</span>
                                                <span style={{fontWeight: 700}}>{v.count}</span>
                                            </div>
                                        ))}
                                    </div>
                                )}
                                {correlationData.port_states && correlationData.port_states.length > 0 && (
                                    <div>
                                        <p style={{color: '#d4d4d8', fontWeight: 600, marginBottom: '0.25rem'}}>PORT STATES</p>
                                        {correlationData.port_states.map((p, i) => (
                                            <div key={i} style={{display: 'flex', justifyContent: 'space-between', padding: '0.2rem 0'}}>
                                                <span style={{textTransform: 'capitalize'}}>{p.state}</span>
                                                <span style={{fontWeight: 700}}>{p.count}</span>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
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
                <div style={{marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                    <h3 style={{fontFamily: 'Space Grotesk, sans-serif', fontSize: '1.25rem', fontWeight: 700, color: '#18181b'}}>
                        NETWORK OVERVIEW
                    </h3>
                    <button
                        onClick={() => setShowTopology(!showTopology)}
                        style={{
                            padding: '0.5rem 1rem',
                            borderRadius: '8px',
                            border: '1px solid #e4e4e7',
                            background: showTopology ? 'var(--accent-green)' : '#fff',
                            color: showTopology ? '#18181b' : '#52525b',
                            fontSize: '0.75rem',
                            fontWeight: 700,
                            cursor: 'pointer',
                            transition: 'all 0.2s',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.5rem'
                        }}
                    >
                        <Network size={16} />
                        {showTopology ? 'HIDE TOPOLOGY' : 'SHOW TOPOLOGY'}
                    </button>
                </div>

                {showTopology && topologyData && (
                    <div style={{
                        marginBottom: '1.5rem',
                        padding: '1.5rem',
                        background: '#fff',
                        border: '1px solid #e4e4e7',
                        borderRadius: '12px',
                        minHeight: '300px'
                    }}>
                        <h4 style={{fontSize: '0.8rem', fontWeight: 700, marginBottom: '1rem', color: '#18181b'}}>TOPOLOGY MAP</h4>
                        <div style={{display: 'flex', flexWrap: 'wrap', gap: '1rem', justifyContent: 'center'}}>
                            {topologyData.nodes && topologyData.nodes.map((node, i) => (
                                <div
                                    key={i}
                                    style={{
                                        padding: '0.75rem 1rem',
                                        borderRadius: '8px',
                                        border: `2px solid ${node.vulnerable ? '#ef4444' : '#22c55e'}`,
                                        background: node.vulnerable ? '#fef2f2' : '#f0fdf4',
                                        minWidth: '100px',
                                        textAlign: 'center'
                                    }}
                                >
                                    <div style={{fontSize: '0.8rem', fontWeight: 700, color: '#18181b'}}>{node.label}</div>
                                    <div style={{fontSize: '0.65rem', color: '#71717a', marginTop: '0.25rem'}}>{node.vendor}</div>
                                    <div style={{fontSize: '0.6rem', color: '#71717a'}}>{node.open_ports} open</div>
                                </div>
                            ))}
                        </div>
                        {topologyData.edges && topologyData.edges.length > 0 && (
                            <div style={{marginTop: '1rem', fontSize: '0.7rem', color: '#71717a', textAlign: 'center'}}>
                                {topologyData.edges.length} connections shown
                            </div>
                        )}
                    </div>
                )}

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
                            {/* Tabs */}
                            <div className="details-tabs" style={{display: 'flex', gap: '0.25rem', marginBottom: '1.5rem', borderBottom: '1px solid #e4e4e7', paddingBottom: '0.5rem'}}>
                                {['info', 'vulns', 'geo', 'health', 'probes'].map(tab => (
                                    <button
                                        key={tab}
                                        onClick={() => setActiveTab(tab)}
                                        style={{
                                            padding: '0.5rem 0.75rem',
                                            borderRadius: '6px',
                                            border: 'none',
                                            background: activeTab === tab ? '#3f3f46' : 'transparent',
                                            color: activeTab === tab ? '#fff' : '#71717a',
                                            fontSize: '0.65rem',
                                            fontWeight: 700,
                                            cursor: 'pointer',
                                            textTransform: 'uppercase',
                                            transition: 'all 0.2s'
                                        }}
                                    >
                                        {tab === 'vulns' ? 'Vulns' : tab === 'geo' ? 'Geo' : tab === 'health' ? 'Health' : tab}
                                    </button>
                                ))}
                            </div>

                            {activeTab === 'info' && (
                                <>
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
                                </>
                            )}

                            {activeTab === 'vulns' && (
                                <div>
                                    <h4 className="section-title">VULNERABILITIES ({vulnerabilities.length})</h4>
                                    {vulnerabilities.length === 0 ? (
                                        <p style={{fontSize: '0.8rem', color: '#71717a'}}>No vulnerabilities detected</p>
                                    ) : (
                                        <div style={{display: 'flex', flexDirection: 'column', gap: '0.75rem'}}>
                                            {vulnerabilities.map((v, i) => (
                                                <div key={i} style={{
                                                    padding: '1rem',
                                                    background: '#fafafa',
                                                    border: '1px solid #e4e4e7',
                                                    borderRadius: '12px',
                                                    borderLeft: `4px solid ${v.severity === 'critical' ? '#ef4444' : v.severity === 'high' ? '#f97316' : v.severity === 'medium' ? '#eab308' : '#71717a'}`
                                                }}>
                                                    <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem'}}>
                                                        <b style={{fontSize: '0.85rem'}}>{v.cve_id || 'Unknown CVE'}</b>
                                                        <span style={{
                                                            fontSize: '0.6rem',
                                                            fontWeight: 800,
                                                            padding: '0.25rem 0.5rem',
                                                            borderRadius: '4px',
                                                            background: v.severity === 'critical' ? '#fee2e2' : v.severity === 'high' ? '#fed7aa' : v.severity === 'medium' ? '#fef3c7' : '#f4f4f5',
                                                            color: v.severity === 'critical' ? '#ef4444' : v.severity === 'high' ? '#f97316' : v.severity === 'medium' ? '#d97706' : '#71717a',
                                                            textTransform: 'uppercase'
                                                        }}>{v.severity}</span>
                                                    </div>
                                                    {v.description && <p style={{fontSize: '0.75rem', color: '#52525b', marginBottom: '0.5rem'}}>{v.description}</p>}
                                                    <div style={{fontSize: '0.7rem', color: '#71717a', display: 'flex', gap: '1rem'}}>
                                                        {v.cvss_score && <span>CVSS: {v.cvss_score}</span>}
                                                        {v.port && <span>Port: {v.port}</span>}
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            )}

                            {activeTab === 'geo' && (
                                <div>
                                    <h4 className="section-title">GEOLOCATION</h4>
                                    {loadingGeo ? (
                                        <p style={{fontSize: '0.8rem', color: '#71717a'}}>Loading geolocation data...</p>
                                    ) : geoData ? (
                                        <div style={{display: 'flex', flexDirection: 'column', gap: '0.75rem'}}>
                                            {geoData.country && (
                                                <div className="stat-box" style={{textAlign: 'left'}}>
                                                    <p className="stat-label">COUNTRY</p>
                                                    <b>{geoData.country}</b>
                                                </div>
                                            )}
                                            {geoData.region && (
                                                <div className="stat-box" style={{textAlign: 'left'}}>
                                                    <p className="stat-label">REGION</p>
                                                    <b>{geoData.region}</b>
                                                </div>
                                            )}
                                            {geoData.city && (
                                                <div className="stat-box" style={{textAlign: 'left'}}>
                                                    <p className="stat-label">CITY</p>
                                                    <b>{geoData.city}</b>
                                                </div>
                                            )}
                                            {geoData.org && (
                                                <div className="stat-box" style={{textAlign: 'left'}}>
                                                    <p className="stat-label">ORGANIZATION</p>
                                                    <b>{geoData.org}</b>
                                                </div>
                                            )}
                                            {geoData.asn && (
                                                <div className="stat-box" style={{textAlign: 'left'}}>
                                                    <p className="stat-label">ASN</p>
                                                    <b>{geoData.asn}</b>
                                                </div>
                                            )}
                                            {!geoData.country && !geoData.city && (
                                                <p style={{fontSize: '0.8rem', color: '#71717a'}}>No geolocation data available</p>
                                            )}
                                        </div>
                                    ) : (
                                        <p style={{fontSize: '0.8rem', color: '#71717a'}}>Select a device to view geolocation</p>
                                    )}
                                </div>
                            )}

                            {activeTab === 'health' && (
                                <div>
                                    <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem'}}>
                                        <h4 className="section-title" style={{marginBottom: 0}}>HEALTH HISTORY</h4>
                                        <select
                                            value={healthHours}
                                            onChange={(e) => setHealthHours(parseInt(e.target.value))}
                                            style={{
                                                padding: '0.4rem 0.6rem',
                                                borderRadius: '6px',
                                                border: '1px solid #e4e4e7',
                                                background: '#fff',
                                                fontSize: '0.7rem',
                                                cursor: 'pointer'
                                            }}
                                        >
                                            <option value={24}>24 Hours</option>
                                            <option value={48}>48 Hours</option>
                                            <option value={72}>72 Hours</option>
                                        </select>
                                    </div>
                                    {healthHistory.length === 0 ? (
                                        <p style={{fontSize: '0.8rem', color: '#71717a'}}>No health history available</p>
                                    ) : (
                                        <div style={{display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '300px', overflowY: 'auto'}}>
                                            {healthHistory.map((h, i) => (
                                                <div key={i} style={{
                                                    padding: '0.75rem 1rem',
                                                    background: '#f4f4f5',
                                                    borderRadius: '8px',
                                                    display: 'flex',
                                                    justifyContent: 'space-between',
                                                    alignItems: 'center'
                                                }}>
                                                    <div>
                                                        <span style={{fontSize: '0.7rem', color: '#71717a'}}>{h.timestamp ? new Date(h.timestamp).toLocaleString() : 'N/A'}</span>
                                                    </div>
                                                    <div style={{display: 'flex', gap: '1rem', fontSize: '0.75rem'}}>
                                                        <span style={{color: h.status === 'healthy' ? '#22c55e' : h.status === 'warning' ? '#eab308' : '#ef4444'}}>
                                                            {h.status || 'unknown'}
                                                        </span>
                                                        {h.latency_ms && <span style={{color: '#52525b'}}>{h.latency_ms.toFixed(1)}ms</span>}
                                                        {h.packet_loss !== null && <span style={{color: h.packet_loss > 5 ? '#ef4444' : '#52525b'}}>{h.packet_loss}% loss</span>}
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            )}

                            {activeTab === 'probes' && (
                                <div>
                                    <h4 className="section-title">MANUAL SERVICE PROBES</h4>
                                    <div style={{display: 'flex', gap: '0.5rem', marginBottom: '1rem'}}>
                                        <input
                                            type="text"
                                            placeholder="e.g., 22,80,443"
                                            value={probePorts}
                                            onChange={(e) => setProbePorts(e.target.value)}
                                            style={{
                                                flex: 1,
                                                padding: '0.6rem 0.75rem',
                                                borderRadius: '8px',
                                                border: '1px solid #e4e4e7',
                                                fontSize: '0.75rem',
                                                fontFamily: 'Inter, sans-serif',
                                                outline: 'none'
                                            }}
                                        />
                                        <button
                                            onClick={handleManualProbe}
                                            disabled={probing || !selected}
                                            style={{
                                                padding: '0.6rem 1rem',
                                                borderRadius: '8px',
                                                border: 'none',
                                                background: probing ? '#a1a1aa' : 'var(--accent-green)',
                                                color: probing ? '#fff' : '#18181b',
                                                fontWeight: 700,
                                                fontSize: '0.75rem',
                                                cursor: probing ? 'not-allowed' : 'pointer',
                                                transition: 'all 0.2s'
                                            }}
                                        >
                                            {probing ? 'PROBING...' : 'PROBE'}
                                        </button>
                                    </div>
                                    {probeResults && (
                                        <div style={{display: 'flex', flexDirection: 'column', gap: '0.75rem'}}>
                                            {probeResults.probes && probeResults.probes.map((p, i) => (
                                                <div key={i} style={{
                                                    padding: '1rem',
                                                    background: '#fafafa',
                                                    border: '1px solid #e4e4e7',
                                                    borderRadius: '12px'
                                                }}>
                                                    <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem'}}>
                                                        <b style={{fontSize: '0.85rem'}}>Port {p.port}</b>
                                                        <span style={{fontSize: '0.7rem', color: p.error ? '#ef4444' : '#22c55e'}}>
                                                            {p.error || p.service}
                                                        </span>
                                                    </div>
                                                    {p.banner && <p style={{fontSize: '0.75rem', color: '#52525b', marginBottom: '0.25rem'}}>Banner: {p.banner}</p>}
                                                    {p.version && <p style={{fontSize: '0.75rem', color: '#52525b', marginBottom: '0.25rem'}}>Version: {p.version}</p>}
                                                    {p.confidence && (
                                                        <div style={{fontSize: '0.7rem', color: '#71717a'}}>
                                                            Confidence: <span style={{
                                                                color: p.confidence > 0.8 ? '#22c55e' : p.confidence > 0.5 ? '#eab308' : '#ef4444',
                                                                fontWeight: 700
                                                            }}>{Math.round(p.confidence * 100)}%</span>
                                                        </div>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                </>
            )}
        </div>
    );
};

export default App;
