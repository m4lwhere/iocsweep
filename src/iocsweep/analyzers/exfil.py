"""
Data exfiltration detection for IOCSweep.

Detects potential data exfiltration patterns including:
- Asymmetric traffic analysis (high outbound ratio)
- Large data transfers to external IPs
- Unusual port usage
- Encrypted exfiltration
- DNS tunneling data volume
"""

from __future__ import annotations

from collections import defaultdict

from iocsweep.models import DataExfiltration, NetworkConnection, Protocol, Severity
from iocsweep.utils.entropy import calculate_entropy


class ExfilAnalyzer:
    """
    Detect potential data exfiltration in network traffic.

    Exfiltration detection is based on:
    - Unusual outbound data volumes
    - Asymmetric traffic patterns
    - Communication to unusual destinations
    - High entropy in outbound data
    """

    # Ports commonly used for exfiltration
    EXFIL_PORTS = {
        53: 'DNS (possible tunneling)',
        80: 'HTTP',
        443: 'HTTPS',
        8080: 'HTTP Proxy',
        8443: 'HTTPS Alt',
        22: 'SSH',
        21: 'FTP',
        25: 'SMTP',
        587: 'SMTP Submission',
        465: 'SMTPS',
        993: 'IMAPS',
        995: 'POP3S',
        1194: 'OpenVPN',
        4443: 'Pharos',
        8000: 'HTTP Alt',
        9001: 'Tor',
    }

    # Thresholds
    MIN_BYTES_THRESHOLD = 1_000_000  # 1 MB minimum to flag
    HIGH_RATIO_THRESHOLD = 10.0  # 10:1 outbound:inbound ratio
    VERY_HIGH_RATIO_THRESHOLD = 50.0  # 50:1 ratio

    def __init__(
        self,
        min_bytes: int = 1_000_000,
        ratio_threshold: float = 10.0,
    ):
        """
        Initialize exfiltration analyzer.

        Args:
            min_bytes: Minimum bytes to consider for exfil
            ratio_threshold: Minimum outbound:inbound ratio to flag
        """
        self.min_bytes = min_bytes
        self.ratio_threshold = ratio_threshold

    def detect_exfil(
        self,
        connections: list[NetworkConnection],
    ) -> list[DataExfiltration]:
        """
        Detect potential data exfiltration from connection data.

        Args:
            connections: List of network connections

        Returns:
            List of potential exfiltration events
        """
        suspects = []

        # Aggregate by destination
        dest_stats: dict[str, dict] = defaultdict(
            lambda: {'sent': 0, 'received': 0, 'port': 0, 'protocol': Protocol.UNKNOWN}
        )

        for conn in connections:
            # Skip internal connections
            if self._is_private_ip(conn.dst_ip):
                continue

            key = f"{conn.dst_ip}:{conn.dst_port}"
            dest_stats[key]['sent'] += conn.bytes_sent
            dest_stats[key]['received'] += conn.bytes_received
            dest_stats[key]['port'] = conn.dst_port
            dest_stats[key]['protocol'] = conn.protocol
            dest_stats[key]['first_seen'] = conn.first_seen

        # Analyze each destination
        for dest, stats in dest_stats.items():
            bytes_sent = stats['sent']
            bytes_received = stats['received']

            # Skip if not enough data sent
            if bytes_sent < self.min_bytes:
                continue

            # Calculate ratio
            ratio = bytes_sent / bytes_received if bytes_received > 0 else float('inf')

            # Check if suspicious
            is_suspicious = False
            reasons = []

            if ratio >= self.VERY_HIGH_RATIO_THRESHOLD:
                is_suspicious = True
                reasons.append(f'Very high outbound ratio: {ratio:.1f}:1')
            elif ratio >= self.ratio_threshold:
                is_suspicious = True
                reasons.append(f'High outbound ratio: {ratio:.1f}:1')

            # Check for large transfer
            if bytes_sent > 100_000_000:  # 100 MB
                is_suspicious = True
                reasons.append(f'Large data transfer: {bytes_sent/1_000_000:.1f} MB')

            # Check for DNS exfil (unusual volume over DNS)
            if stats['port'] == 53 and bytes_sent > 100_000:  # 100 KB over DNS
                is_suspicious = True
                reasons.append('Unusual DNS traffic volume')

            if is_suspicious:
                parts = dest.rsplit(':', 1)
                dst_ip = parts[0]
                dst_port = int(parts[1]) if len(parts) > 1 else 0

                suspects.append(DataExfiltration(
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    bytes_sent=bytes_sent,
                    bytes_received=bytes_received,
                    ratio=ratio,
                    protocol=stats['protocol'],
                    is_suspicious=True,
                    suspicion_reasons=reasons,
                    timestamp=stats.get('first_seen'),
                ))

        # Sort by bytes sent (highest first)
        suspects.sort(key=lambda x: x.bytes_sent, reverse=True)

        return suspects

    def analyze_dns_exfil(
        self,
        dns_records: list,
        threshold_bytes: int = 50_000,
    ) -> list[DataExfiltration]:
        """
        Analyze DNS traffic for tunneling/exfiltration.

        Args:
            dns_records: List of DNS records
            threshold_bytes: Minimum bytes to flag

        Returns:
            List of potential DNS exfiltration events
        """
        suspects = []

        # Group by base domain
        domain_data: dict[str, dict] = defaultdict(
            lambda: {'query_count': 0, 'total_length': 0, 'avg_entropy': 0.0, 'queries': []}
        )

        for record in dns_records:
            # Extract base domain (last 2 parts)
            parts = record.query_name.rstrip('.').split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
            else:
                base_domain = record.query_name

            domain_data[base_domain]['query_count'] += 1
            domain_data[base_domain]['total_length'] += len(record.query_name)
            domain_data[base_domain]['queries'].append(record.query_name)

            if record.entropy:
                avg = domain_data[base_domain]['avg_entropy']
                count = domain_data[base_domain]['query_count']
                domain_data[base_domain]['avg_entropy'] = (avg * (count - 1) + record.entropy) / count

        # Analyze each domain
        for domain, data in domain_data.items():
            reasons = []
            is_suspicious = False

            # High query count
            if data['query_count'] > 100:
                is_suspicious = True
                reasons.append(f"High query count: {data['query_count']}")

            # Large total data volume
            if data['total_length'] > threshold_bytes:
                is_suspicious = True
                reasons.append(f"High data volume: {data['total_length']} bytes")

            # High average entropy
            if data['avg_entropy'] > 3.5:
                is_suspicious = True
                reasons.append(f"High entropy subdomains: {data['avg_entropy']:.2f}")

            if is_suspicious:
                suspects.append(DataExfiltration(
                    dst_ip=domain,  # Using domain as dst
                    dst_port=53,
                    bytes_sent=data['total_length'],
                    bytes_received=0,
                    ratio=float('inf'),
                    protocol=Protocol.DNS,
                    entropy=data['avg_entropy'],
                    is_suspicious=True,
                    suspicion_reasons=reasons,
                ))

        return suspects

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        private_prefixes = (
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '192.168.',
            '127.',
            '0.',
            '169.254.',  # Link-local
        )
        return ip.startswith(private_prefixes)

    def get_exfil_summary(self, suspects: list[DataExfiltration]) -> dict:
        """Generate exfiltration summary."""
        if not suspects:
            return {
                'total_suspects': 0,
                'total_bytes_exfil': 0,
                'top_destinations': [],
            }

        return {
            'total_suspects': len(suspects),
            'total_bytes_exfil': sum(s.bytes_sent for s in suspects),
            'top_destinations': [
                {
                    'ip': s.dst_ip,
                    'port': s.dst_port,
                    'bytes': s.bytes_sent,
                    'ratio': f'{s.ratio:.1f}:1' if s.ratio != float('inf') else 'inf',
                    'reasons': s.suspicion_reasons,
                }
                for s in suspects[:10]
            ],
        }

    def format_bytes(self, bytes_val: int) -> str:
        """Format bytes in human-readable form."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f'{bytes_val:.1f} {unit}'
            bytes_val /= 1024
        return f'{bytes_val:.1f} PB'
