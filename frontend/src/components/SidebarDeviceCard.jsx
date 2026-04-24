import React, { memo } from 'react';

const SidebarDeviceCard = memo(function SidebarDeviceCard({ device, isSelected, onClick }) {
    const openPorts = device.ports.filter(p => p.state === 'open').length;
    
    return (
        <div
            onClick={() => onClick(device)}
            className={`device-card ${isSelected ? 'selected' : ''} ${device.vulns_detected ? 'vuln' : ''}`}
        >
            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                <span className="device-ip">{device.ip}</span>
                <div className={`status-indicator ${device.vulns_detected ? 'status-red' : 'status-green'}`} />
            </div>
            <p className="device-vendor">{device.vendor}</p>
            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.4rem', fontSize: '0.6rem', color: '#71717a', gap: '0.5rem'}}>
                <span>{openPorts} open ports</span>
                {device.hop_count !== null && device.hop_count !== undefined && (
                    <span style={{color: '#3b82f6', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.15rem'}}>
                        ↗ {device.hop_count} hop{device.hop_count !== 1 ? 's' : ''}
                    </span>
                )}
                {device.vulns_detected && <span style={{color: '#ef4444', fontWeight: 700}}>⚠ VULN</span>}
            </div>
        </div>
    );
});

export default SidebarDeviceCard;
