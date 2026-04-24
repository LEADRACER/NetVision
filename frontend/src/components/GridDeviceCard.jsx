import React, { memo } from 'react';
import { Shield, ShieldAlert } from 'lucide-react';

const GridDeviceCard = memo(function GridDeviceCard({ device, onClick }) {
    return (
        <div
            onClick={() => onClick(device)}
            className={`grid-card ${device.vulns_detected ? 'vuln' : ''}`}
        >
            <div className="grid-card-header">
                <div className={`grid-card-icon ${device.vulns_detected ? 'vuln' : 'safe'}`}>
                    {device.vulns_detected ? <ShieldAlert size={24} color="#ef4444" /> : <Shield size={24} color="#22c55e" />}
                </div>
                <div>
                    <h3 className="grid-card-title">{device.ip}</h3>
                    <p className="grid-card-subtitle">{device.vendor}</p>
                </div>
            </div>
            <div className="grid-card-tags">
                {device.ports.slice(0, 3).map(p => (
                    <span key={p.port} className="port-tag">
                        {p.port}
                    </span>
                ))}
            </div>
        </div>
    );
});

export default GridDeviceCard;
