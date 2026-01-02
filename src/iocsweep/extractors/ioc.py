"""
IOC extraction and detection for IOCSweep.

Automatically extracts and identifies IOCs from network traffic:
- IP addresses (IPv4/IPv6)
- Domain names
- URLs
- Email addresses
- File hashes (MD5, SHA1, SHA256)
- JA3/JA3S hashes
- Bitcoin addresses
- CVE identifiers
"""

from __future__ import annotations

import re
from typing import Pattern

from iocsweep.models import IOCType


class IOCExtractor:
    """
    Extract and identify Indicators of Compromise from data.

    Supports automatic detection of:
    - IPv4/IPv6 addresses
    - Domain names
    - URLs
    - Email addresses
    - File hashes
    - JA3/JA3S fingerprints
    - Bitcoin/Cryptocurrency addresses
    - CVE identifiers
    """

    # Regex patterns for IOC types
    PATTERNS: dict[IOCType, Pattern] = {
        IOCType.IP_ADDRESS: re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        IOCType.DOMAIN: re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        ),
        IOCType.URL: re.compile(
            r'https?://[^\s<>"\']+',
            re.IGNORECASE
        ),
        IOCType.EMAIL: re.compile(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        ),
        IOCType.FILE_HASH_MD5: re.compile(
            r'\b[a-fA-F0-9]{32}\b'
        ),
        IOCType.FILE_HASH_SHA1: re.compile(
            r'\b[a-fA-F0-9]{40}\b'
        ),
        IOCType.FILE_HASH_SHA256: re.compile(
            r'\b[a-fA-F0-9]{64}\b'
        ),
        IOCType.JA3: re.compile(
            r'\b[a-fA-F0-9]{32}\b'  # JA3 is MD5 format
        ),
    }

    # IPv6 pattern (separate due to complexity)
    IPV6_PATTERN = re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|'
        r'\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|'
        r'\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|'
        r'\b::(?:ffff(:0{1,4})?:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )

    # Bitcoin address pattern
    BITCOIN_PATTERN = re.compile(
        r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b'
    )

    # CVE pattern
    CVE_PATTERN = re.compile(
        r'\bCVE-\d{4}-\d{4,}\b',
        re.IGNORECASE
    )

    # Known false positive domains to filter
    FALSE_POSITIVE_DOMAINS = {
        'localhost',
        'localdomain',
        'example.com',
        'example.org',
        'example.net',
        'invalid',
        'test',
        'local',
    }

    # Known false positive IPs
    FALSE_POSITIVE_IPS = {
        '0.0.0.0',
        '255.255.255.255',
        '127.0.0.1',
    }

    def __init__(self):
        """Initialize IOC extractor."""
        pass

    def detect_ioc_type(self, value: str) -> IOCType | None:
        """
        Detect the type of an IOC value.

        Args:
            value: The potential IOC value

        Returns:
            IOCType if detected, None otherwise
        """
        value = value.strip()

        # Check URL first (most specific)
        if self.PATTERNS[IOCType.URL].match(value):
            return IOCType.URL

        # Check email
        if self.PATTERNS[IOCType.EMAIL].fullmatch(value):
            return IOCType.EMAIL

        # Check IP address
        if self.PATTERNS[IOCType.IP_ADDRESS].fullmatch(value):
            return IOCType.IP_ADDRESS

        # Check IPv6
        if self.IPV6_PATTERN.fullmatch(value):
            return IOCType.IP_ADDRESS

        # Check hashes by length
        if re.fullmatch(r'[a-fA-F0-9]{64}', value):
            return IOCType.FILE_HASH_SHA256
        if re.fullmatch(r'[a-fA-F0-9]{40}', value):
            return IOCType.FILE_HASH_SHA1
        if re.fullmatch(r'[a-fA-F0-9]{32}', value):
            return IOCType.FILE_HASH_MD5  # Could also be JA3

        # Check domain (after IP to avoid false positives)
        if self.PATTERNS[IOCType.DOMAIN].fullmatch(value):
            if not self._is_false_positive_domain(value):
                return IOCType.DOMAIN

        return None

    def extract_from_text(self, text: str) -> dict[IOCType, set[str]]:
        """
        Extract all IOCs from text content.

        Args:
            text: Text content to extract IOCs from

        Returns:
            Dictionary mapping IOC types to sets of extracted values
        """
        results: dict[IOCType, set[str]] = {t: set() for t in IOCType}

        # Extract URLs
        for url in self.PATTERNS[IOCType.URL].findall(text):
            results[IOCType.URL].add(url)

        # Extract emails
        for email in self.PATTERNS[IOCType.EMAIL].findall(text):
            if not self._is_false_positive_email(email):
                results[IOCType.EMAIL].add(email.lower())

        # Extract IP addresses
        for ip in self.PATTERNS[IOCType.IP_ADDRESS].findall(text):
            if ip not in self.FALSE_POSITIVE_IPS:
                results[IOCType.IP_ADDRESS].add(ip)

        # Extract IPv6 addresses
        for ipv6 in self.IPV6_PATTERN.findall(text):
            results[IOCType.IP_ADDRESS].add(ipv6)

        # Extract domains (filter carefully)
        for domain in self.PATTERNS[IOCType.DOMAIN].findall(text):
            if not self._is_false_positive_domain(domain):
                # Verify it's not an IP
                if not self.PATTERNS[IOCType.IP_ADDRESS].fullmatch(domain):
                    results[IOCType.DOMAIN].add(domain.lower())

        # Extract hashes
        for sha256 in self.PATTERNS[IOCType.FILE_HASH_SHA256].findall(text):
            results[IOCType.FILE_HASH_SHA256].add(sha256.lower())

        for sha1 in self.PATTERNS[IOCType.FILE_HASH_SHA1].findall(text):
            # Verify it's not a substring of SHA256
            if sha1.lower() not in ''.join(results[IOCType.FILE_HASH_SHA256]):
                results[IOCType.FILE_HASH_SHA1].add(sha1.lower())

        for md5 in self.PATTERNS[IOCType.FILE_HASH_MD5].findall(text):
            # Verify it's not a substring of longer hashes
            if not any(md5.lower() in h for h in results[IOCType.FILE_HASH_SHA1]):
                if not any(md5.lower() in h for h in results[IOCType.FILE_HASH_SHA256]):
                    results[IOCType.FILE_HASH_MD5].add(md5.lower())

        # Extract Bitcoin addresses
        for btc in self.BITCOIN_PATTERN.findall(text):
            if self._validate_bitcoin(btc):
                results.setdefault('bitcoin', set()).add(btc)

        # Extract CVEs
        for cve in self.CVE_PATTERN.findall(text):
            results.setdefault('cve', set()).add(cve.upper())

        return results

    def extract_from_bytes(self, data: bytes) -> dict[IOCType, set[str]]:
        """
        Extract IOCs from binary data.

        Args:
            data: Binary data to extract IOCs from

        Returns:
            Dictionary mapping IOC types to sets of extracted values
        """
        # Try different encodings
        for encoding in ['utf-8', 'latin-1', 'ascii']:
            try:
                text = data.decode(encoding, errors='replace')
                return self.extract_from_text(text)
            except Exception:
                continue

        return {t: set() for t in IOCType}

    def _is_false_positive_domain(self, domain: str) -> bool:
        """Check if domain is a known false positive."""
        domain_lower = domain.lower()

        # Check against known false positives
        if domain_lower in self.FALSE_POSITIVE_DOMAINS:
            return True

        # Check TLD only domains
        if '.' not in domain_lower:
            return True

        # Check if it ends with false positive TLD
        for fp in self.FALSE_POSITIVE_DOMAINS:
            if domain_lower.endswith(f'.{fp}'):
                return True

        return False

    def _is_false_positive_email(self, email: str) -> bool:
        """Check if email is a known false positive."""
        email_lower = email.lower()

        # Check for example domains
        if any(fp in email_lower for fp in ['example.com', 'example.org', 'test.com']):
            return True

        return False

    def _validate_bitcoin(self, address: str) -> bool:
        """Basic Bitcoin address validation."""
        # Very basic validation - just check length and format
        if address.startswith('bc1'):
            return 39 <= len(address) <= 62
        elif address.startswith(('1', '3')):
            return 25 <= len(address) <= 35
        return False

    def defang_ioc(self, ioc: str, ioc_type: IOCType) -> str:
        """
        Defang an IOC for safe sharing.

        Args:
            ioc: The IOC value
            ioc_type: Type of IOC

        Returns:
            Defanged IOC string
        """
        if ioc_type == IOCType.IP_ADDRESS:
            return ioc.replace('.', '[.]')
        elif ioc_type == IOCType.DOMAIN:
            return ioc.replace('.', '[.]')
        elif ioc_type == IOCType.URL:
            return ioc.replace('http', 'hxxp').replace('.', '[.]').replace('://', '[://]')
        elif ioc_type == IOCType.EMAIL:
            return ioc.replace('@', '[@]').replace('.', '[.]')
        return ioc

    def refang_ioc(self, ioc: str) -> str:
        """
        Refang a defanged IOC.

        Args:
            ioc: The defanged IOC value

        Returns:
            Refanged IOC string
        """
        return (ioc
                .replace('[.]', '.')
                .replace('[@]', '@')
                .replace('[://]', '://')
                .replace('hxxp', 'http')
                .replace('hXXp', 'http'))
