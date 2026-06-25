"""CVE Lookup — NVD API v2.1 correlation for service version → CVE + CVSS scoring.

Replaces the amateur keyword-match-on-"old"/"vulnerable"/"beta" heuristic with
real version-to-CVE lookup. Uses NVD's public API (no key required for limited use).

Features:
- Service+version → matching CVE query via NVD API
- CVSS v3 scoring & severity classification
- In-memory LRU cache to reduce API calls
- Graceful fallback on network failures (returns empty, doesn't block scan)
"""
import asyncio
import json
import time
from collections import OrderedDict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import httpx
from loguru import logger

log = logger.bind(component="cve_lookup")

# NVD API v2.1 endpoint
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD rate limit: ~5 requests per 30 seconds without an API key
NVD_RATE_LIMIT = 5.0  # seconds between requests
# Cache TTL: 1 hour for CVE results
CACHE_TTL_SECONDS = 3600
# Max CVEs to return per service
MAX_CVES_PER_SERVICE = 5
# Max CVEs to cache
MAX_CACHE_SIZE = 200


class CVESeverity:
    """CVSS v3 severity levels."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


def classify_severity(cvss_score: Optional[float]) -> str:
    """Classify CVSS v3 score into severity level."""
    if cvss_score is None:
        return CVESeverity.UNKNOWN
    if cvss_score >= 9.0:
        return CVESeverity.CRITICAL
    if cvss_score >= 7.0:
        return CVESeverity.HIGH
    if cvss_score >= 4.0:
        return CVESeverity.MEDIUM
    if cvss_score > 0.0:
        return CVESeverity.LOW
    return CVESeverity.NONE


# Common products that often have CVEs — map service name → NVD keyword
SERVICE_PRODUCT_MAP = {
    "apache": "apache http server",
    "nginx": "nginx",
    "openssh": "openssh",
    "ssh": "openssh",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "mariadb": "mariadb",
    "redis": "redis",
    "mongodb": "mongodb",
    "elasticsearch": "elasticsearch",
    "tomcat": "apache tomcat",
    "jenkins": "jenkins",
    "docker": "docker",
    "kubernetes": "kubernetes",
    "nginx-ingress": "nginx",
    "haproxy": "haproxy",
    "varnish": "varnish",
    "squid": "squid",
    "php": "php",
    "node.js": "node.js",
    "python": "python",
    "ruby": "ruby",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "magento": "magento",
    "iis": "microsoft iis",
    "exchange": "microsoft exchange",
    "samba": "samba",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "pure-ftpd": "pure-ftpd",
    "bind": "isc bind",
    "dnsmasq": "dnsmasq",
    "ntp": "ntp",
    "snmp": "snmp",
    "openvpn": "openvpn",
    "openssl": "openssl",
    "bash": "bash",
    "sudo": "sudo",
    "glibc": "glibc",
    "libssh": "libssh",
    "openssl": "openssl",
}


class CVELookupClient:
    """Thread-safe CVE lookup with async API + caching."""

    def __init__(self):
        self._cache: OrderedDict[str, dict] = OrderedDict()
        self._last_request_time: float = 0.0
        self._lock = asyncio.Lock()
        self._session: Optional[httpx.AsyncClient] = None

    async def _ensure_session(self):
        if self._session is None:
            self._session = httpx.AsyncClient(timeout=15.0)

    async def close(self):
        if self._session:
            await self._session.aclose()
            self._session = None

    def _cache_key(self, product: str, version: str) -> str:
        return f"{product.strip().lower()}|{version.strip()}"

    def _get_cached(self, key: str) -> Optional[dict]:
        if key in self._cache:
            entry = self._cache[key]
            if time.time() - entry["ts"] < CACHE_TTL_SECONDS:
                return entry["data"]
            # Expired — remove
            del self._cache[key]
        return None

    def _set_cached(self, key: str, data: dict):
        self._cache[key] = {"ts": time.time(), "data": data}
        # Evict oldest entries if over limit
        while len(self._cache) > MAX_CACHE_SIZE:
            self._cache.popitem(last=False)

    async def _rate_limit(self):
        """Ensure we don't exceed NVD's rate limits."""
        async with self._lock:
            elapsed = time.time() - self._last_request_time
            if elapsed < NVD_RATE_LIMIT:
                await asyncio.sleep(NVD_RATE_LIMIT - elapsed)
            self._last_request_time = time.time()

    async def lookup(
        self, product: str, version: str
    ) -> Tuple[List[Dict], Optional[str]]:
        """Look up CVEs for a service product + version.
        
        Returns:
            (cve_list, error_message)
            cve_list: list of dicts with cve_id, cvss_score, severity, description
            error_message: None on success, str on failure
        """
        if not product or not version:
            return [], None

        cache_key = self._cache_key(product, version)
        cached = self._get_cached(cache_key)
        if cached is not None:
            log.debug("CVE cache hit", product=product, version=version)
            return cached, None

        # Determine the NVD keyword for this product
        product_lower = product.lower()
        nvd_keyword = SERVICE_PRODUCT_MAP.get(product_lower, product_lower)

        # Build search keywords
        keywords = f"{nvd_keyword} {version}"
        log.debug("CVE lookup", keywords=keywords, product=product, version=version)

        try:
            await self._ensure_session()
            results = await self._query_nvd_api(keywords)
            self._set_cached(cache_key, results)
            return results, None
        except Exception as e:
            log.warning("CVE lookup failed", product=product, version=version, error=str(e))
            # Cache empty result to avoid repeated failures
            self._set_cached(cache_key, [])
            return [], str(e)

    async def lookup_many(
        self, services: List[Dict[str, str]]
    ) -> Dict[str, List[Dict]]:
        """Look up CVEs for multiple services in parallel (but rate-limited).
        
        Args:
            services: list of {"product": ..., "version": ...} dicts
        
        Returns:
            {"product|version": [cve_list, ...]}
        """
        results = {}
        for svc in services:
            product = svc.get("product", "")
            version = svc.get("version", "")
            cves, _ = await self.lookup(product, version)
            key = f"{product}|{version}"
            results[key] = cves
        return results

    async def _query_nvd_api(self, keywords: str) -> List[Dict]:
        """Query the NVD API v2.1 for CVEs matching the keywords."""
        await self._rate_limit()

        params = {
            "keywordSearch": keywords,
            "resultsPerPage": min(MAX_CVES_PER_SERVICE, 10),
        }

        try:
            response = await self._session.get(
                NVD_API_BASE,
                params=params,
                headers={"User-Agent": "NetVision/5.0 (scan correlation)"},
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                log.warning("NVD API rate limited (403)")
            elif e.response.status_code == 404:
                log.debug("NVD API no results for keywords", keywords=keywords)
                return []
            raise

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return []

        results = []
        for vuln in vulnerabilities[:MAX_CVES_PER_SERVICE]:
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id", "UNKNOWN")

            # Extract CVSS v3 metrics
            metrics = cve_item.get("metrics", {})
            cvss_v3_data = (
                metrics.get("cvssMetricV31", [{}])[0]
                or metrics.get("cvssMetricV30", [{}])[0]
                or {}
            )
            cvss_data = cvss_v3_data.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = classify_severity(cvss_score)

            # Get description
            descriptions = cve_item.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # Get references
            refs = cve_item.get("references", [])
            reference_urls = [r.get("url") for r in refs[:5] if r.get("url")]

            results.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity,
                "description": description[:300],  # Truncate to keep it compact
                "reference_urls": reference_urls,
                "matched_keywords": keywords,
            })

        return results

    async def batch_scan_vulnerabilities(
        self, devices: List[Dict], db=None
    ) -> List[Dict]:
        """Correlate all scanned devices for vulnerabilities.
        
        Called after a scan completes. Checks each device's ports for
        version strings, looks up CVEs, and stores results in DB.
        
        Args:
            devices: list of device dicts from scanner (ports with version info)
            db: optional Database instance to persist results
        
        Returns:
            list of all found vulnerability dicts
        """
        all_cves = []

        for device in devices:
            device_ip = device.get("ip")
            for port in device.get("ports", []):
                service_name = port.get("service", "")
                version = port.get("version", "")
                product = port.get("product", "") or service_name

                if not version or not product:
                    continue

                cves, _ = await self.lookup(product, version)
                for cve in cves:
                    cve_entry = {
                        "device_ip": device_ip,
                        "port": port.get("port"),
                        "service": service_name,
                        "product": product,
                        "version": version,
                        **cve,
                    }
                    all_cves.append(cve_entry)

                    # Persist to DB if available
                    if db and hasattr(db, "add_vulnerability"):
                        try:
                            db.add_vulnerability(
                                device_id=None,  # Will be resolved if needed
                                port_id=port.get("port"),
                                vuln_data={
                                    "cve_id": cve["cve_id"],
                                    "cvss_score": cve["cvss_score"],
                                    "severity": cve["severity"],
                                    "description": cve["description"],
                                    "reference_urls": ",".join(cve.get("reference_urls", [])),
                                },
                            )
                        except Exception as e:
                            log.warning("Failed to persist vulnerability", error=str(e))

        if all_cves:
            log.info("CVE correlation complete", total_cves=len(all_cves))

        return all_cves
