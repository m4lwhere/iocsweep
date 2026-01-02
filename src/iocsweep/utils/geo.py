"""
Geolocation and ASN lookup utilities for IOCSweep.

Provides:
- IP geolocation (country, city, coordinates)
- ASN/ISP information
- Whois data extraction
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Any

from iocsweep.models import GeoLocation


class GeoLookup:
    """
    IP geolocation and ASN lookup service.

    Supports:
    - MaxMind GeoIP2/GeoLite2 databases
    - IPWhois lookups (online)
    - Caching for performance
    """

    # Private IP ranges
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('224.0.0.0/4'),  # Multicast
        ipaddress.ip_network('240.0.0.0/4'),  # Reserved
    ]

    # Known cloud/hosting ASNs
    CLOUD_ASNS = {
        # AWS
        16509: 'Amazon AWS',
        14618: 'Amazon AWS',
        # Google
        15169: 'Google Cloud',
        396982: 'Google Cloud',
        # Microsoft/Azure
        8075: 'Microsoft Azure',
        8068: 'Microsoft',
        # Cloudflare
        13335: 'Cloudflare',
        # DigitalOcean
        14061: 'DigitalOcean',
        # OVH
        16276: 'OVH',
        # Linode
        63949: 'Linode',
        # Vultr
        20473: 'Vultr',
        # Hetzner
        24940: 'Hetzner',
    }

    # High-risk countries (for threat scoring)
    HIGH_RISK_COUNTRIES = {
        'RU', 'CN', 'KP', 'IR', 'SY', 'BY', 'VE', 'CU',
    }

    def __init__(self, maxmind_db_path: Path | str | None = None):
        """
        Initialize geolocation lookup.

        Args:
            maxmind_db_path: Path to MaxMind GeoLite2 or GeoIP2 database
        """
        self.maxmind_reader = None
        self.asn_reader = None

        if maxmind_db_path:
            self._load_maxmind(Path(maxmind_db_path))

    def _load_maxmind(self, db_path: Path) -> None:
        """Load MaxMind database."""
        try:
            import maxminddb

            if db_path.is_file():
                self.maxmind_reader = maxminddb.open_database(str(db_path))
            elif db_path.is_dir():
                # Look for common database files
                for db_name in ['GeoLite2-City.mmdb', 'GeoIP2-City.mmdb', 'GeoLite2-Country.mmdb']:
                    db_file = db_path / db_name
                    if db_file.exists():
                        self.maxmind_reader = maxminddb.open_database(str(db_file))
                        break

                # Also look for ASN database
                for asn_name in ['GeoLite2-ASN.mmdb', 'GeoIP2-ASN.mmdb']:
                    asn_file = db_path / asn_name
                    if asn_file.exists():
                        self.asn_reader = maxminddb.open_database(str(asn_file))
                        break

        except ImportError:
            pass  # maxminddb not installed
        except Exception:
            pass  # Database load error

    @lru_cache(maxsize=10000)
    def lookup(self, ip: str) -> GeoLocation | None:
        """
        Look up geolocation for an IP address.

        Args:
            ip: IP address to look up

        Returns:
            GeoLocation object or None if lookup fails
        """
        # Check if private IP
        if self._is_private(ip):
            return GeoLocation(
                country='Private',
                country_code='--',
                asn_org='Private Network',
            )

        geo = GeoLocation()

        # Try MaxMind first
        if self.maxmind_reader:
            try:
                result = self.maxmind_reader.get(ip)
                if result:
                    geo = self._parse_maxmind_result(result)
            except Exception:
                pass

        # Try ASN lookup
        if self.asn_reader:
            try:
                asn_result = self.asn_reader.get(ip)
                if asn_result:
                    geo.asn = asn_result.get('autonomous_system_number')
                    geo.asn_org = asn_result.get('autonomous_system_organization')
            except Exception:
                pass

        # Fallback to ipwhois if no MaxMind
        if not self.maxmind_reader and not geo.country:
            geo = self._lookup_ipwhois(ip)

        return geo

    def _parse_maxmind_result(self, result: dict) -> GeoLocation:
        """Parse MaxMind lookup result."""
        geo = GeoLocation()

        # Country info
        if 'country' in result:
            geo.country = result['country'].get('names', {}).get('en')
            geo.country_code = result['country'].get('iso_code')

        # City info
        if 'city' in result:
            geo.city = result['city'].get('names', {}).get('en')

        # Region/state
        if 'subdivisions' in result and result['subdivisions']:
            geo.region = result['subdivisions'][0].get('names', {}).get('en')

        # Coordinates
        if 'location' in result:
            geo.latitude = result['location'].get('latitude')
            geo.longitude = result['location'].get('longitude')

        # ISP info (if available in database)
        if 'traits' in result:
            geo.isp = result['traits'].get('isp')
            geo.asn = result['traits'].get('autonomous_system_number')
            geo.asn_org = result['traits'].get('autonomous_system_organization')

        return geo

    def _lookup_ipwhois(self, ip: str) -> GeoLocation:
        """Fallback lookup using ipwhois."""
        geo = GeoLocation()

        try:
            from ipwhois import IPWhois

            obj = IPWhois(ip)
            result = obj.lookup_rdap(asn_methods=['dns', 'whois'])

            geo.asn = result.get('asn')
            geo.asn_org = result.get('asn_description')
            geo.country_code = result.get('asn_country_code')

            # Get network info
            if 'network' in result:
                network = result['network']
                geo.country = network.get('country')

        except ImportError:
            pass  # ipwhois not installed
        except Exception:
            pass  # Lookup failed

        return geo

    def _is_private(self, ip: str) -> bool:
        """Check if IP is in private range."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in network for network in self.PRIVATE_RANGES)
        except Exception:
            return False

    def is_high_risk_country(self, ip: str) -> bool:
        """Check if IP is from a high-risk country."""
        geo = self.lookup(ip)
        if geo and geo.country_code:
            return geo.country_code.upper() in self.HIGH_RISK_COUNTRIES
        return False

    def is_cloud_ip(self, ip: str) -> tuple[bool, str | None]:
        """
        Check if IP belongs to a known cloud provider.

        Returns:
            Tuple of (is_cloud, provider_name)
        """
        geo = self.lookup(ip)
        if geo and geo.asn:
            provider = self.CLOUD_ASNS.get(geo.asn)
            return (provider is not None, provider)
        return (False, None)

    def get_country_stats(self, ips: list[str]) -> dict[str, int]:
        """
        Get country distribution for a list of IPs.

        Args:
            ips: List of IP addresses

        Returns:
            Dictionary mapping country names to counts
        """
        stats: dict[str, int] = {}

        for ip in ips:
            geo = self.lookup(ip)
            if geo and geo.country:
                stats[geo.country] = stats.get(geo.country, 0) + 1

        return dict(sorted(stats.items(), key=lambda x: x[1], reverse=True))

    def close(self) -> None:
        """Close database connections."""
        if self.maxmind_reader:
            self.maxmind_reader.close()
        if self.asn_reader:
            self.asn_reader.close()
