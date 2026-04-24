import React, { memo } from 'react';
import { Shield, ShieldAlert } from 'lucide-react';

const GridDeviceCard = memo(function GridDeviceCard({ device, onClick }) {
    const openPorts = device.ports.filter(p => p.state === 'open').length;

    return (
        <div
            onClick={() => onClick(device)}
            className={`grid-card ${device.vulns_detected ? 'vuln' : ''}`}
        >
            <div className="grid-card-tags" style={{position: 'absolute', top: '1rem', right: '1rem'}}>
                <span
                    className="port-tag"
                    style={{
                        background: device.vulns_detected ? '#fee2e2' : '#f0fdf4',
                        borderColor: device.vulns_detected ? '#f87171' : '#86efac',
                        color: device.vulns_detected ? '#991b1b' : '#166534'
                    }}
                >
                    {openPorts} open
                </span>
            </div>

            <div className="grid-card-header">
                <div className={`grid-card-icon ${device.vulns_detected ? 'vuln' : 'safe'}`}>
                    {device.vulns_detected ? <ShieldAlert size={24} color="#ef4444" /> : <Shield size={24} color="#22c55e" />}
                </div>
                <div>
                    <h3 className="grid-card-title">
                        {device.ip}
                        {device.hop_count !== null && device.hop_count !== undefined && (
                            <span style={{
                                fontSize: '0.7rem',
                                fontWeight: 400,
                                color: '#3b82f6',
                                marginLeft: '0.5rem',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.15rem'
                            }}>
                                ↗ {device.hop_count}
                            </span>
                        )}
                    </h3>
                    <p className="grid-card-subtitle">
                        {device.vendor}
                        {device.hop_count !== null && device.hop_count !== undefined && (
                            <span style={{color: '#3b82f6'}}> · {device.hop_count} hop{device.hop_count !== 1 ? 's' : ''} away</span>
                        )}
                    </p>
                    {device.os && device.os !== 'Unknown' && (
                        <p className="grid-card-os" title={device.os}>{device.os}</p>
                    )}
                </div>
            </div>

            <div className="grid-card-tags">
                {device.ports.slice(0, 4).map(p => (
                    <span
                        key={`${p.port}-${p.protocol}`}
                        className={`port-tag ${p.state === 'open' ? 'important' : ''}`}
                        title={`${p.service}${p.version ? ' ' + p.version : ''}`}
                    >
                        {p.port}{p.protocol === 'tcp' ? '' : p.protocol.charAt(0)}
                        {p.state === 'open' && ' ▲'}
                    </span>
                ))}
            </div>
        </div>
    );
});

export default GridDeviceCard;
