"""
geoip.py — GeoIP Lookup
Resolves IP addresses to geographic location using ip-api.com (free, no API key required).
Results are cached in memory to avoid redundant requests.
"""

import logging
import requests
import re
from functools import lru_cache

logger = logging.getLogger("siem.geoip")

# Private/reserved IP ranges — skip lookup for these
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.", "::1"
)


def _is_private(ip: str) -> bool:
    """Return True if the IP is private, loopback or reserved."""
    if not ip:
        return True
    return any(ip.startswith(prefix) for prefix in _PRIVATE_PREFIXES)


@lru_cache(maxsize=512)
def lookup(ip: str) -> dict:
    """
    Look up geographic info for an IP address.
    Returns a dict with country, city, isp and org fields.
    Results are cached — repeated lookups for the same IP are free.
    Returns empty dict for private/reserved IPs or on error.
    """
    match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', ip)

    if not match:
        logger.debug(f"[GeoIP] No IP found in string: {ip}")
        return {}

    ip = match.group(0)

    
    if _is_private(ip):
        return {"country": "Internal", "city": "Private Network", "isp": "N/A"}

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=3,
            params={"fields": "status,country,regionName,city,isp,org,query"}
        )
        data = response.json()
        if data.get("status") == "success":
            return {
                "country":  data.get("country", "Unknown"),
                "region":   data.get("regionName", ""),
                "city":     data.get("city", "Unknown"),
                "isp":      data.get("isp", "Unknown"),
                "org":      data.get("org", ""),
            }
    except Exception as e:
        logger.debug(f"[GeoIP] Lookup failed for {ip}: {e}")

    return {}
