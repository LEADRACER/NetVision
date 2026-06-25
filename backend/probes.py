import socket
import ssl
import subprocess
import json
from typing import Dict, Optional, List
import asyncio
from dataclasses import dataclass, field
from loguru import logger

log = logger.bind(component="probes")

@dataclass
class ServiceProbeResult:
    service: str
    version: Optional[str]
    banner: Optional[str]
    extra_info: Dict
    confidence: int  # 0-100
    cve_ids: List[str] = field(default_factory=list)

class ServiceProbe:
    """Base class for service-specific probes."""
    port: int = None
    protocol: str = 'tcp'

    async def probe(self, ip: str, port: int) -> ServiceProbeResult:
        raise NotImplementedError

class HTTPProbe(ServiceProbe):
    port = 80
    protocol = 'tcp'
    service = 'http'

    async def probe(self, ip: str, port: int) -> ServiceProbeResult:
        result = ServiceProbeResult(service='http', version=None, banner=None, extra_info={}, confidence=0)
        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=3)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"http://{ip}:{port}/"
                async with session.get(url, allow_redirects=False) as resp:
                    server = resp.headers.get('Server', '')
                    result.banner = server
                    result.version = self._parse_version(server)
                    result.extra_info = {
                        'status_code': resp.status,
                        'headers': dict(resp.headers),
                        'content_type': resp.headers.get('Content-Type')
                    }
                    result.confidence = 80
        except ImportError:
            # aiohttp not available — socket fallback
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                result.banner = banner.split('\r\n')[0] if banner else None
                result.version = self._parse_version(result.banner)
                result.confidence = 60
            except Exception:
                pass
        except Exception as e:
            # aiohttp installed but request failed — socket fallback
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                result.banner = banner.split('\r\n')[0] if banner else None
                result.version = self._parse_version(result.banner)
                result.confidence = 50
            except Exception:
                pass
        return result

    def _parse_version(self, server_header: str) -> Optional[str]:
        if not server_header:
            return None
        # Apache/2.4.41 → 2.4.41
        # nginx/1.18.0 → 1.18.0
        import re
        match = re.search(r'[/\s](\d+\.\d+\.?\d*)', server_header)
        return match.group(1) if match else server_header[:50]

class HTTPSProbe(ServiceProbe):
    port = 443
    protocol = 'tcp'
    service = 'https'

    async def probe(self, ip: str, port: int) -> ServiceProbeResult:
        result = ServiceProbeResult(service='https', version=None, banner=None, extra_info={}, confidence=0)
        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=3)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"https://{ip}:{port}/"
                async with session.get(url, allow_redirects=False, ssl=False) as resp:
                    server = resp.headers.get('Server', '')
                    result.banner = server
                    result.version = HTTPProbe()._parse_version(server)
                    # SSL/TLS info
                    try:
                        ssl_obj = resp.connection.transport.get_ssl_object() if resp.connection and resp.connection.transport else None
                    except Exception:
                        ssl_obj = None
                    if ssl_obj:
                        result.extra_info['tls_version'] = ssl_obj.version()
                        result.extra_info['cipher'] = ssl_obj.cipher()
                    result.extra_info['status_code'] = resp.status
                    result.extra_info['headers'] = dict(resp.headers)
                    result.confidence = 80
        except ImportError:
            # aiohttp not available — socket+ssl fallback
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        ssock.connect((ip, port))
                        cipher = ssock.cipher()
                        version = ssock.version()
                        result.banner = f"TLS {version} ({cipher[0] if cipher else 'unknown'})"
                        result.version = version
                        result.extra_info = {'tls_version': version, 'cipher': cipher}
                        result.confidence = 70
            except Exception:
                pass
        except Exception as e:
            # aiohttp installed but request failed — socket+ssl fallback
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        ssock.connect((ip, port))
                        cipher = ssock.cipher()
                        version = ssock.version()
                        result.banner = f"TLS {version} ({cipher[0] if cipher else 'unknown'})"
                        result.version = version
                        result.extra_info = {'tls_version': version, 'cipher': cipher}
                        result.confidence = 70
            except Exception:
                pass
        return result

class SSHProbe(ServiceProbe):
    port = 22
    protocol = 'tcp'
    service = 'ssh'

    async def probe(self, ip: str, port: int) -> ServiceProbeResult:
        result = ServiceProbeResult(service='ssh', version=None, banner=None, extra_info={}, confidence=0)
        try:
            import asyncssh
            # Just connect and read banner, don't authenticate
            conn = await asyncio.wait_for(
                asyncssh.connect(ip, port=port, username='test', password='test', known_hosts=None),
                timeout=2
            )
            result.banner = conn.get_extra_info('banner', '').strip()
            result.version = self._parse_version(result.banner)
            result.extra_info = {'key_algorithms': conn.get_extra_info('key_algorithms', [])}
            result.confidence = 90
            conn.close()
        except (ImportError, Exception):
            # asyncssh not available or failed — socket fallback
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                result.banner = banner
                result.version = self._parse_version(banner)
                result.confidence = 60
            except Exception:
                pass
        return result

    def _parse_version(self, banner: str) -> Optional[str]:
        if not banner:
            return None
        # SSH-2.0-OpenSSH_8.2p1 → 8.2p1
        import re
        match = re.search(r'SSH-\d+\.\d+[-\s](\S+)', banner)
        return match.group(1) if match else banner[:30]

class DNSProbe(ServiceProbe):
    port = 53
    protocol = 'udp'
    service = 'dns'

    async def probe(self, ip: str, port: int) -> ServiceProbeResult:
        result = ServiceProbeResult(service='dns', version=None, banner=None, extra_info={}, confidence=50)
        try:
            import dns.resolver
            # Simple A record query for google.com to test responsiveness
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ip]
            resolver.timeout = 2
            resolver.lifetime = 2
            try:
                answer = resolver.resolve('google.com', 'A')
                result.extra_info['test_query'] = 'success'
                result.extra_info['records'] = [str(r) for r in answer[:3]]
                result.confidence = 90
            except dns.resolver.NXDOMAIN:
                result.extra_info['test_query'] = 'nxdomain'
                result.confidence = 80
            except Exception:
                result.extra_info['test_query'] = 'timeout'
        except ImportError:
            # Raw socket query
            try:
                # Build DNS query packet (simplified)
                import struct
                # DNS header: ID=0x1234, flags=0x0100 (standard query), qdcount=1
                transaction_id = b'\x12\x34'
                flags = b'\x01\x00'  # Standard query
                qdcount = struct.pack('!H', 1)
                ancount = nsount = arcount = b'\x00\x00'
                question = b'\x00\x00'  # qtype=A
                qclass = b'\x00\x01'   # qclass=IN
                # Encode domain: len+label repeated, null terminator
                domain = b'\x03www\x05google\x03com\x00'
                dns_query = transaction_id + flags + qdcount + ancount + nsount + arcount + domain + question + qclass

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(dns_query, (ip, port))
                response, _ = sock.recvfrom(512)
                if response:
                    result.extra_info['response_size'] = len(response)
                    result.confidence = 70
            except Exception:
                pass
        return result

class SMBProbe(ServiceProbe):
    port = 445
    protocol = 'tcp'
    service = 'smb'

    async def probe(self, ip: str, port: int) -> ServiceProbeResult:
        result = ServiceProbeResult(service='smb', version=None, banner=None, extra_info={}, confidence=40)
        try:
            # Use smbprotocol library if available
            pass
        except Exception:
            pass
        return result

# Registry of all probes
PROBES = {
    80: HTTPProbe(),
    443: HTTPSProbe(),
    22: SSHProbe(),
    53: DNSProbe(),
    445: SMBProbe(),
    # Add more as needed
}

async def probe_service(ip: str, port: int, protocol: str = 'tcp') -> ServiceProbeResult:
    """Run appropriate probe for a given port."""
    probe = PROBES.get(port)
    if not probe:
        return ServiceProbeResult(service='unknown', version=None, banner=None, extra_info={}, confidence=0)
    try:
        return await probe.probe(ip, port)
    except Exception as e:
        log.warning("Probe failed", ip=ip, port=port, probe=probe.service, error=str(e))
        return ServiceProbeResult(service=probe.service, version=None, banner=None, extra_info={'error': str(e)}, confidence=0)
