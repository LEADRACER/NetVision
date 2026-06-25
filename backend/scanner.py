"""Network scanner — nmap wrapper with async chunked scanning, traceroute, OUI detection."""

import nmap
import asyncio
import socket
import struct
import fcntl
import os
import json
import subprocess
from scapy.all import IP, ICMP, sr1, conf
from loguru import logger

log = logger.bind(component="scanner")

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
    "04:D4:C4": "Samsung", "00:00:F0": "Samsung", "00:07:AB": "Samsung",
}


class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        conf.verb = 0  # Reduce scapy verbosity

    def get_local_subnet(self, interface=None):
        """Auto-detect active interface from default route, fallback to discovery."""
        if not interface:
            try:
                result = subprocess.run(
                    ["ip", "route", "get", "1.1.1.1"],
                    capture_output=True, text=True, timeout=3,
                )
                if result.returncode == 0:
                    parts = result.stdout.strip().split()
                    if "dev" in parts:
                        dev_idx = parts.index("dev")
                        interface = parts[dev_idx + 1]
                        log.info("Detected active interface", interface=interface)
            except Exception:
                pass

        if interface:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                cur_ip = socket.inet_ntoa(fcntl.ioctl(
                    s.fileno(),
                    0x8915,
                    struct.pack("256s", interface.encode("utf-8")[:15]),
                )[20:24])
                subnet = ".".join(cur_ip.split(".")[:-1]) + ".0/24"
                log.info("Local subnet resolved", interface=interface, subnet=subnet)
                return subnet
            except Exception as e:
                log.warning("Could not get subnet from interface", interface=interface, error=str(e))

        # Final fallback — discover any non-loopback interface
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", "up"],
                capture_output=True, text=True, timeout=3,
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("inet ") and "127.0.0.1" not in line:
                    parts = line.split()
                    ip_with_cidr = parts[1]
                    ip_parts = ip_with_cidr.split("/")[0].split(".")
                    subnet = f"{'.'.join(ip_parts[:3])}.0/24"
                    log.info("Fallback subnet discovered", subnet=subnet)
                    return subnet
        except Exception:
            pass

        log.warning("No active interface found, using loopback")
        return "127.0.0.0/24"

    @staticmethod
    def _get_subnet_from_ip(ip):
        if not ip:
            return None
        parts = ip.split(".")[:3]
        return f"{'.'.join(parts)}.0/24"

    async def traceroute(self, target, max_ttl=20):
        hops = []
        try:
            target_ip = socket.gethostbyname(target) if not target.replace(".", "").isdigit() else target
        except Exception as e:
            log.error("Could not resolve target", target=target, error=str(e))
            return hops

        log.info("Traceroute starting", target=target, target_ip=target_ip)

        for ttl in range(1, max_ttl + 1):
            pkt = IP(dst=target_ip, ttl=ttl) / ICMP()
            loop = asyncio.get_event_loop()
            try:
                reply = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2))
                if reply:
                    hop_ip = reply.src
                    rtt = (reply.time * 1000) if hasattr(reply, "time") else 0
                    hops.append({"ip": hop_ip, "ttl": ttl, "rtt": rtt})
                    log.info("Traceroute hop", hop=ttl, ip=hop_ip, rtt_ms=round(rtt, 1))
                    if hop_ip == target_ip:
                        break
                else:
                    hops.append({"ip": None, "ttl": ttl, "rtt": None})
            except Exception as e:
                log.warning("Traceroute error at hop", hop=ttl, error=str(e))
                hops.append({"ip": None, "ttl": ttl, "rtt": None})

        return hops

    async def scan_network(
        self, target=None, profile="deep", callback=None,
        duration=None, subnet_callback=None, trace_hops=False,
    ):
        if not target:
            target = self.get_local_subnet()

        # Handle multiple targets
        targets = []
        if target.lower() == "all":
            targets = [
                "192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24",
                "10.0.0.0/24", "172.16.0.0/24",
            ]
        elif "," in target:
            targets = [t.strip() for t in target.split(",")]
        else:
            targets = [target]

        # If trace_hops enabled, traceroute first and add hop subnets
        subnet_to_hop = {}
        if trace_hops and len(targets) == 1:
            hops = await self.traceroute(targets[0])
            for hop in hops:
                if hop["ip"]:
                    hop_subnet = self._get_subnet_from_ip(hop["ip"])
                    if hop_subnet and hop_subnet not in subnet_to_hop:
                        subnet_to_hop[hop_subnet] = hop["ttl"]
            for subnet in subnet_to_hop:
                if subnet not in targets:
                    targets.append(subnet)
            log.info("Hop trace complete", hops_found=len(subnet_to_hop), total_subnets=len(targets))

        # Profile mappings
        profiles = {
            "quick": "-T5 -F --max-retries 1",
            "deep": "-T4 -O -sV",
            "security": "-T4 -O -sV --script vuln",
        }
        base_args = profiles.get(profile, profiles["deep"])

        # Apply duration timeouts
        if duration:
            try:
                dur_sec = int(duration)
                max_rtt = min(2000, max(100, dur_sec * 8))
                base_args += f" --max-rtt-timeout {max_rtt}ms --min-rtt-timeout 50ms --host-timeout {dur_sec}s"
            except ValueError:
                pass

        log.info("Scan starting", profile=profile, subnet_count=len(targets), targets=targets)

        all_devices = []
        for idx, subnet in enumerate(targets):
            log.info("Scanning subnet", current=idx + 1, total=len(targets), subnet=subnet)

            if subnet_callback:
                asyncio.create_task(subnet_callback(subnet))

            hop_distance = subnet_to_hop.get(subnet) if trace_hops else None

            if subnet.endswith("/24"):
                base_ip = ".".join(subnet.split(".")[:-1])
                for start in range(1, 255, 16):
                    end = min(start + 15, 254)
                    chunk_target = f"{base_ip}.{start}-{end}"
                    loop = asyncio.get_event_loop()
                    try:
                        scan_data = await loop.run_in_executor(
                            None, lambda: self.nm.scan(hosts=chunk_target, arguments=base_args)
                        )
                        results = self.parse_results(scan_data, hop_distance)
                        if callback and results:
                            await callback(results)
                        all_devices.extend(results)
                    except Exception as e:
                        log.warning("Chunk scan failed", chunk=chunk_target, error=str(e))
            else:
                loop = asyncio.get_event_loop()
                try:
                    scan_data = await loop.run_in_executor(
                        None, lambda: self.nm.scan(hosts=subnet, arguments=base_args)
                    )
                    results = self.parse_results(scan_data, hop_distance)
                    if callback and results:
                        await callback(results)
                    all_devices.extend(results)
                except Exception as e:
                    log.warning("Subnet scan failed", subnet=subnet, error=str(e))

        result = {"status": "complete", "subnets_scanned": len(targets), "devices_found": len(all_devices)}
        log.info("Scan finished", **result)
        return result

    def parse_results(self, scan_data, hop_distance=None):
        devices = []
        for host in self.nm.all_hosts():
            latency = self.nm[host].get("times", {}).get("srtt", 500)
            ms_latency = int(latency) / 1000
            mac = self.nm[host].get("addresses", {}).get("mac", "UNKNOWN")
            vendor = self.nm[host].get("vendor", {}).get(mac, "Unknown")

            if vendor == "Unknown" and mac != "UNKNOWN":
                prefix = ":".join(mac.split(":")[:3]).upper()
                vendor = OUI_MAP.get(prefix, "Manufacturer Unknown")

            distance = hop_distance if hop_distance is not None else max(1, int(ms_latency / 2))

            host_data = {
                "ip": host,
                "mac": mac,
                "vendor": vendor,
                "hostname": self.nm[host].hostname(),
                "status": self.nm[host].state(),
                "os": "Unknown",
                "ports": [],
                "latency_ms": ms_latency,
                "distance": distance,
                "strength": 0,
                "vulns_detected": False,
                "hop_count": hop_distance,
            }

            if "osmatch" in self.nm[host] and self.nm[host]["osmatch"]:
                host_data["os"] = self.nm[host]["osmatch"][0]["name"]

            all_ports = 0
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                all_ports += len(ports)
                for port in ports:
                    service = self.nm[host][proto][port]
                    host_data["ports"].append({
                        "port": port,
                        "protocol": proto,
                        "state": service.get("state"),
                        "service": service.get("name"),
                        "version": service.get("version"),
                        "product": service.get("product"),
                    })
                    if service.get("version") and any(
                        v in service.get("version").lower()
                        for v in ["old", "vulnerable", "beta"]
                    ):
                        host_data["vulns_detected"] = True

            host_data["strength"] = min(100, (all_ports * 10) + 20)
            devices.append(host_data)

        log.debug("Parsed scan results", hosts=len(devices))
        return devices
