import nmap
import asyncio
import socket
import struct
import fcntl
import os
import json

# Common OUI mappings for instant manufacturer identification
OUI_MAP = {
    "00:05:02": "Apple", "00:03:93": "Apple", "3C:D0:F8": "Apple", "F0:18:98": "Apple",
    "00:1E:C2": "Apple", "00:25:00": "Apple", "00:25:BC": "Apple", "00:26:BB": "Apple",
    "D8:0D:17": "Apple", "E4:25:E7": "Apple", "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "00:15:5D": "Microsoft", "00:03:FF": "Microsoft",
    "00:16:3E": "Xen", "00:1C:42": "Parallels", "08:00:27": "Oracle VirtualBox",
    "A4:77:33": "Google", "00:1A:11": "Google", "F4:F5:D8": "Google",
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco",
    "00:11:22": "Dell", "00:14:22": "Dell", "00:15:C5": "Dell",
    "04:D4:C4": "Samsung", "00:00:F0": "Samsung", "00:07:AB": "Samsung"
}

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def get_local_subnet(self, interface='eth0'):
        # Helper to get the local subnet of a given interface
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cur_ip = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', interface.encode('utf-8')[:15])
            )[20:24])
            subnet = ".".join(cur_ip.split(".")[:-1]) + ".0/24"
            return subnet
        except Exception as e:
            print(f"Error getting subnet for {interface}: {e}")
            return "192.168.1.0/24"

    async def scan_network(self, target=None, profile="deep", callback=None, duration=None, subnet_callback=None):
        if not target:
            target = self.get_local_subnet()
        
        # Handle multiple targets (comma-separated or "all" keyword)
        targets = []
        if target.lower() == "all":
            # Most common home/office /24 subnets (not exhaustive RFC1918 to avoid hours-long scans)
            targets = [
                "192.168.0.0/24",
                "192.168.1.0/24",
                "192.168.2.0/24",
                "10.0.0.0/24",
                "172.16.0.0/24"
            ]
        elif ',' in target:
            targets = [t.strip() for t in target.split(',')]
        else:
            targets = [target]
        
        # Profile mappings
        profiles = {
            "quick": "-T5 -F --max-retries 1",
            "deep": "-T4 -O -sV",
            "security": "-T4 -O -sV --script vuln"
        }
        base_args = profiles.get(profile, profiles["deep"])
        
        # Apply duration-based timeouts if specified
        if duration:
            try:
                dur_sec = int(duration)
                max_rtt = min(2000, max(100, dur_sec * 8))
                base_args += f" --max-rtt-timeout {max_rtt}ms --min-rtt-timeout 50ms --host-timeout {dur_sec}s"
            except ValueError:
                pass
        
        print(f"[*] Starting {profile} scan on {len(targets)} subnet(s)...")
        
        # Scan each target sequentially
        for idx, subnet in enumerate(targets):
            print(f"[*] Scanning subnet {idx + 1}/{len(targets)}: {subnet}")
            
            # Notify about new subnet
            if subnet_callback:
                asyncio.create_task(subnet_callback(subnet))
            
            # For /24 or larger, chunk the scan
            if subnet.endswith("/24"):
                base_ip = ".".join(subnet.split(".")[:-1])
                for start in range(1, 255, 16):
                    end = min(start + 15, 254)
                    chunk_target = f"{base_ip}.{start}-{end}"
                    
                    loop = asyncio.get_event_loop()
                    try:
                        scan_data = await loop.run_in_executor(None, lambda: self.nm.scan(hosts=chunk_target, arguments=base_args))
                        results = self.parse_results(scan_data)
                        if callback and results:
                            await callback(results)
                    except Exception as e:
                        print(f"[!] Chunk {chunk_target} failed: {e}")
            else:
                # Single host or custom range
                loop = asyncio.get_event_loop()
                try:
                    scan_data = await loop.run_in_executor(None, lambda: self.nm.scan(hosts=subnet, arguments=base_args))
                    results = self.parse_results(scan_data)
                    if callback and results:
                        await callback(results)
                except Exception as e:
                    print(f"[!] Scan of {subnet} failed: {e}")
        
        return {"status": "complete", "subnets_scanned": len(targets)}

    def parse_results(self, scan_data):
        devices = []
        for host in self.nm.all_hosts():
            # Latency and Strength heuristics
            latency = self.nm[host].get('times', {}).get('srtt', 500)
            ms_latency = int(latency) / 1000
            
            # Manufacturer Lookup
            mac = self.nm[host].get('addresses', {}).get('mac', "UNKNOWN")
            vendor = self.nm[host].get('vendor', {}).get(mac, "Unknown")
            
            # Fallback to local OUI map if vendor is generic
            if vendor == "Unknown" and mac != "UNKNOWN":
                prefix = ":".join(mac.split(":")[:3]).upper()
                vendor = OUI_MAP.get(prefix, "Manufacturer Unknown")

            host_data = {
                "ip": host,
                "mac": mac,
                "vendor": vendor,
                "hostname": self.nm[host].hostname(),
                "status": self.nm[host].state(),
                "os": "Unknown",
                "ports": [],
                "latency_ms": ms_latency,
                "distance": max(1, int(ms_latency / 2)),
                "strength": 0,
                "vulns_detected": False # Placeholder for future vuln script integration
            }
            
            # OS detection results
            if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                host_data["os"] = self.nm[host]['osmatch'][0]['name']
            
            # Port and Service info
            all_ports = 0
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                all_ports += len(ports)
                for port in ports:
                    service = self.nm[host][proto][port]
                    host_data["ports"].append({
                        "port": port,
                        "protocol": proto,
                        "state": service.get('state'),
                        "service": service.get('name'),
                        "version": service.get('version'),
                        "product": service.get('product')
                    })
                    
                    # Heuristic for vulns based on service versions (simplified)
                    if service.get('version') and any(v in service.get('version').lower() for v in ['old', 'vulnerable', 'beta']):
                        host_data["vulns_detected"] = True
            
            # Strength based on service richness
            host_data["strength"] = min(100, (all_ports * 10) + 20)
            
            devices.append(host_data)
            
        return devices

if __name__ == "__main__":
    # Test script
    scanner = NetworkScanner()
    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(scanner.scan_network("127.0.0.1")) # Scan localhost as a test
    print(results)
