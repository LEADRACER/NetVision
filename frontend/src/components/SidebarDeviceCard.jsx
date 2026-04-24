import React, { memo } from 'react';

const SidebarDeviceCard = memo(function SidebarDeviceCard({ device, isSelected, onClick }) {
    return (
        <div
            onClick={() => onClick(device)}
            className={`device-card ${isSelected ? 'selected' : ''} ${device.vulns_detected ? 'vuln' : ''}`}
        >
            <div className="device-info">
                <span className="device-ip">{device.ip}</span>
                <div className={`status-indicator ${device.vulns_detected ? 'status-red' : 'status-green'}`} />
            </div>
            <p className="device-vendor">{device.vendor}</p>
        </div>
    );
});

export default SidebarDeviceCard;
