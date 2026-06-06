import requests
import sqlite3
from typing import Optional, Dict, List
import time

class GeoLocator:
    """IP Geolocation using free IP API (ip-api.com)."""
    
    def __init__(self, db, cache_ttl: int = 86400):
        """
        Args:
            db: Database instance for caching
            cache_ttl: Cache time-to-live in seconds (default: 24h)
        """
        self.db = db
        self.cache_ttl = cache_ttl
        self.base_url = "http://ip-api.com/json/{}?fields=status,message,country,region,city,as,lat,lon"

    def lookup(self, ip: str, force_refresh: bool = False) -> Optional[Dict]:
        """
        Look up geolocation for an IP.
        Returns dict with country, region, city, asn, org, lat/lon or None.
        """
        # Check cache first
        if not force_refresh:
            cached = self.db.get_geolocation(ip)
            if cached:
                # Check if cache is still fresh
                import datetime
                updated = datetime.datetime.fromisoformat(cached['updated_at'])
                if (datetime.datetime.now() - updated).total_seconds() < self.cache_ttl:
                    return {
                        'country': cached['country'],
                        'region': cached['region'],
                        'city': cached['city'],
                        'asn': cached['asn'],
                        'org': cached['org'],
                        'latitude': cached['latitude'],
                        'longitude': cached['longitude']
                    }
        
        # Fetch from API
        try:
            url = self.base_url.format(ip)
            response = requests.get(url, timeout=5)
            data = response.json()
            
            if data.get('status') == 'success':
                geo = {
                    'country': data.get('country'),
                    'region': data.get('region'),
                    'city': data.get('city'),
                    'asn': data.get('as', '').split(' ')[0] if data.get('as') else None,
                    'org': data.get('as', '').split(' ', 1)[1] if data.get('as') else None,
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon')
                }
                self.db.cache_geolocation(ip, geo)
                return geo
            else:
                print(f"[!] Geo lookup failed for {ip}: {data.get('message', 'Unknown error')}")
        except Exception as e:
            print(f"[!] Geo lookup error for {ip}: {e}")
        
        return None

    async def batch_lookup(self, ips: List[str]) -> Dict[str, Dict]:
        """Look up multiple IPs, uses cache when possible."""
        results = {}
        for ip in ips:
            results[ip] = self.lookup(ip)
        return results
