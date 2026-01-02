"""
DNS packet analyzer for IOCSweep.

Extracts maximum intelligence from DNS traffic including:
- Query/response parsing
- DGA detection
- DNS tunneling detection
- Suspicious TLD analysis
- Fast-flux detection
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from typing import Any

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

from iocsweep.models import DNSRecord, Severity
from iocsweep.utils.entropy import calculate_entropy


class DNSAnalyzer:
    """Advanced DNS traffic analyzer."""

    # Suspicious TLDs often used in malware campaigns
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs
        'top', 'xyz', 'club', 'online', 'site', 'wang',  # Cheap/abused TLDs
        'buzz', 'work', 'click', 'link', 'surf',
        'bid', 'trade', 'webcam', 'date', 'review',
        'stream', 'download', 'racing', 'cricket',
        'science', 'party', 'gdn', 'men', 'loan',
    }

    # Known DNS over HTTPS providers (could indicate bypass attempts)
    DOH_PROVIDERS = {
        'cloudflare-dns.com', 'dns.google', 'dns.quad9.net',
        'doh.opendns.com', 'dns.nextdns.io', 'doh.cleanbrowsing.org',
    }

    # Common DNS query types
    QUERY_TYPES = {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        6: 'SOA',
        12: 'PTR',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
        33: 'SRV',
        35: 'NAPTR',
        43: 'DS',
        46: 'RRSIG',
        47: 'NSEC',
        48: 'DNSKEY',
        52: 'TLSA',
        65: 'HTTPS',
        99: 'SPF',
        255: 'ANY',
        256: 'URI',
        257: 'CAA',
    }

    def __init__(self):
        """Initialize DNS analyzer."""
        self.domain_response_counts: dict[str, int] = defaultdict(int)
        self.domain_ips: dict[str, set[str]] = defaultdict(set)

    def parse_packet(self, packet: Any, timestamp: datetime) -> list[DNSRecord]:
        """
        Parse DNS packet and extract records.

        Args:
            packet: Scapy packet with DNS layer
            timestamp: Packet timestamp

        Returns:
            List of DNSRecord objects
        """
        records = []

        if not packet.haslayer(DNS):
            return records

        dns = packet[DNS]
        src_ip = packet[IP].src if packet.haslayer(IP) else None
        dst_ip = packet[IP].dst if packet.haslayer(IP) else None

        # Process queries
        if dns.qd:
            for i in range(dns.qdcount):
                try:
                    qr = dns.qd[i] if hasattr(dns.qd, '__getitem__') else dns.qd
                    query_name = qr.qname.decode() if isinstance(qr.qname, bytes) else str(qr.qname)
                    query_type = self.QUERY_TYPES.get(qr.qtype, f"TYPE{qr.qtype}")

                    record = DNSRecord(
                        query_name=query_name,
                        query_type=query_type,
                        timestamp=timestamp,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        is_nx_domain=dns.rcode == 3,
                    )

                    # Analyze for suspicious patterns
                    self._analyze_query(record)
                    records.append(record)
                except Exception:
                    continue

        # Process responses
        if dns.an:
            try:
                rr = dns.an
                while rr:
                    if isinstance(rr, DNSRR):
                        query_name = rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname)
                        query_type = self.QUERY_TYPES.get(rr.type, f"TYPE{rr.type}")

                        # Extract response data
                        response_data = []
                        if hasattr(rr, 'rdata'):
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                try:
                                    rdata = rdata.decode()
                                except Exception:
                                    rdata = rdata.hex()
                            response_data.append(str(rdata))

                            # Track IPs for fast-flux detection
                            if query_type == 'A':
                                self.domain_ips[query_name].add(str(rdata))
                                self.domain_response_counts[query_name] += 1

                        record = DNSRecord(
                            query_name=query_name,
                            query_type=query_type,
                            response_data=response_data,
                            ttl=rr.ttl,
                            timestamp=timestamp,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                        )

                        self._analyze_query(record)

                        # Check for low TTL (fast-flux indicator)
                        if rr.ttl and rr.ttl < 300:
                            record.is_suspicious = True
                            record.suspicion_reasons.append(f"Low TTL: {rr.ttl}s")

                        records.append(record)

                    rr = rr.payload if hasattr(rr, 'payload') and rr.payload else None
            except Exception:
                pass

        return records

    def _analyze_query(self, record: DNSRecord) -> None:
        """Analyze DNS query for suspicious patterns."""
        domain = record.query_name.rstrip('.')

        # Calculate entropy
        subdomain = domain.split('.')[0] if '.' in domain else domain
        record.entropy = calculate_entropy(subdomain)

        # Check for high entropy (DGA indicator)
        if record.entropy > 3.8 and len(subdomain) > 12:
            record.is_suspicious = True
            record.suspicion_reasons.append(f"High entropy subdomain: {record.entropy:.2f}")

        # Check for suspicious TLD
        tld = domain.split('.')[-1].lower() if '.' in domain else ''
        if tld in self.SUSPICIOUS_TLDS:
            record.is_suspicious = True
            record.suspicion_reasons.append(f"Suspicious TLD: .{tld}")

        # Check for long subdomain (possible data exfil)
        if len(subdomain) > 50:
            record.is_suspicious = True
            record.suspicion_reasons.append(f"Long subdomain: {len(subdomain)} chars")

        # Check for hex-like subdomain (encoded data)
        if re.match(r'^[0-9a-f]{20,}$', subdomain.lower()):
            record.is_suspicious = True
            record.suspicion_reasons.append("Hex-encoded subdomain (possible tunneling)")

        # Check for base64-like patterns
        if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', subdomain):
            record.is_suspicious = True
            record.suspicion_reasons.append("Base64-like subdomain (possible tunneling)")

        # Check for numeric-only subdomain
        if subdomain.isdigit() and len(subdomain) > 8:
            record.is_suspicious = True
            record.suspicion_reasons.append("Numeric subdomain (possible encoding)")

        # Check for DoH provider queries (might indicate bypass)
        if any(doh in domain for doh in self.DOH_PROVIDERS):
            record.is_suspicious = True
            record.suspicion_reasons.append("DNS-over-HTTPS provider query")

        # Check for TXT record (often used for tunneling)
        if record.query_type == 'TXT':
            record.is_suspicious = True
            record.suspicion_reasons.append("TXT record query (potential tunneling)")

    def detect_fast_flux(self, min_ips: int = 5) -> dict[str, list[str]]:
        """
        Detect potential fast-flux domains.

        Args:
            min_ips: Minimum unique IPs to flag as fast-flux

        Returns:
            Dictionary of domains with their associated IPs
        """
        fast_flux_domains = {}
        for domain, ips in self.domain_ips.items():
            if len(ips) >= min_ips:
                fast_flux_domains[domain] = list(ips)
        return fast_flux_domains

    def get_tunneling_candidates(self, records: list[DNSRecord]) -> list[DNSRecord]:
        """
        Identify DNS tunneling candidates.

        Args:
            records: List of DNS records

        Returns:
            List of suspicious records that might indicate tunneling
        """
        candidates = []
        for record in records:
            if any("tunneling" in reason.lower() for reason in record.suspicion_reasons):
                candidates.append(record)
        return candidates

    def get_dga_candidates(self, records: list[DNSRecord]) -> list[DNSRecord]:
        """
        Identify potential DGA domains.

        Args:
            records: List of DNS records

        Returns:
            List of records with high-entropy domains
        """
        candidates = []
        for record in records:
            if record.entropy and record.entropy > 3.5:
                candidates.append(record)
        return candidates
