"""
CSV export for IOCSweep analysis results.

Exports analysis results to CSV files suitable for:
- Spreadsheet analysis
- Database import
- Further processing
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import TextIO

from iocsweep.models import AnalysisResult


class CSVExporter:
    """
    Export analysis results to CSV format.

    Creates multiple CSV files for different data types:
    - connections.csv
    - dns.csv
    - http.csv
    - iocs.csv
    - threats.csv
    """

    def __init__(self, delimiter: str = ',', quoting: int = csv.QUOTE_MINIMAL):
        """
        Initialize CSV exporter.

        Args:
            delimiter: Field delimiter
            quoting: CSV quoting style
        """
        self.delimiter = delimiter
        self.quoting = quoting

    def export_all(self, result: AnalysisResult, output_dir: Path | str) -> dict[str, Path]:
        """
        Export all data to multiple CSV files.

        Args:
            result: Analysis result to export
            output_dir: Directory for output files

        Returns:
            Dictionary mapping data type to file path
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        files = {}

        # Export connections
        conn_path = output_dir / 'connections.csv'
        self.export_connections(result, conn_path)
        files['connections'] = conn_path

        # Export DNS
        dns_path = output_dir / 'dns.csv'
        self.export_dns(result, dns_path)
        files['dns'] = dns_path

        # Export HTTP
        http_path = output_dir / 'http.csv'
        self.export_http(result, http_path)
        files['http'] = http_path

        # Export IOCs
        ioc_path = output_dir / 'iocs.csv'
        self.export_iocs(result, ioc_path)
        files['iocs'] = ioc_path

        # Export threats
        threat_path = output_dir / 'threats.csv'
        self.export_threats(result, threat_path)
        files['threats'] = threat_path

        # Export files
        files_path = output_dir / 'extracted_files.csv'
        self.export_files(result, files_path)
        files['files'] = files_path

        # Export credentials
        creds_path = output_dir / 'credentials.csv'
        self.export_credentials(result, creds_path)
        files['credentials'] = creds_path

        return files

    def export_connections(self, result: AnalysisResult, output_path: Path | str) -> None:
        """Export network connections to CSV."""
        headers = [
            'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
            'first_seen', 'last_seen', 'duration_seconds',
            'packet_count', 'bytes_sent', 'bytes_received',
            'src_country', 'src_asn', 'dst_country', 'dst_asn',
        ]

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers, delimiter=self.delimiter, quoting=self.quoting)
            writer.writeheader()

            for conn in result.connections:
                writer.writerow({
                    'src_ip': conn.src_ip,
                    'src_port': conn.src_port,
                    'dst_ip': conn.dst_ip,
                    'dst_port': conn.dst_port,
                    'protocol': conn.protocol.value,
                    'first_seen': conn.first_seen.isoformat(),
                    'last_seen': conn.last_seen.isoformat(),
                    'duration_seconds': conn.duration_seconds,
                    'packet_count': conn.packet_count,
                    'bytes_sent': conn.bytes_sent,
                    'bytes_received': conn.bytes_received,
                    'src_country': conn.src_geo.country if conn.src_geo else '',
                    'src_asn': conn.src_geo.asn if conn.src_geo else '',
                    'dst_country': conn.dst_geo.country if conn.dst_geo else '',
                    'dst_asn': conn.dst_geo.asn if conn.dst_geo else '',
                })

    def export_dns(self, result: AnalysisResult, output_path: Path | str) -> None:
        """Export DNS records to CSV."""
        headers = [
            'timestamp', 'src_ip', 'dst_ip', 'query_name', 'query_type',
            'response_data', 'ttl', 'entropy', 'is_suspicious', 'suspicion_reasons',
        ]

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers, delimiter=self.delimiter, quoting=self.quoting)
            writer.writeheader()

            for dns in result.dns_records:
                writer.writerow({
                    'timestamp': dns.timestamp.isoformat() if dns.timestamp else '',
                    'src_ip': dns.src_ip or '',
                    'dst_ip': dns.dst_ip or '',
                    'query_name': dns.query_name,
                    'query_type': dns.query_type,
                    'response_data': ';'.join(dns.response_data),
                    'ttl': dns.ttl or '',
                    'entropy': f'{dns.entropy:.4f}' if dns.entropy else '',
                    'is_suspicious': dns.is_suspicious,
                    'suspicion_reasons': ';'.join(dns.suspicion_reasons),
                })

    def export_http(self, result: AnalysisResult, output_path: Path | str) -> None:
        """Export HTTP transactions to CSV."""
        headers = [
            'timestamp', 'src_ip', 'dst_ip', 'method', 'host', 'uri',
            'user_agent', 'status_code', 'content_type',
            'is_suspicious', 'suspicion_reasons', 'contains_credentials',
        ]

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers, delimiter=self.delimiter, quoting=self.quoting)
            writer.writeheader()

            for http in result.http_transactions:
                writer.writerow({
                    'timestamp': http.timestamp.isoformat() if http.timestamp else '',
                    'src_ip': http.src_ip or '',
                    'dst_ip': http.dst_ip or '',
                    'method': http.method,
                    'host': http.host,
                    'uri': http.uri,
                    'user_agent': http.user_agent or '',
                    'status_code': http.status_code or '',
                    'content_type': http.content_type or '',
                    'is_suspicious': http.is_suspicious,
                    'suspicion_reasons': ';'.join(http.suspicion_reasons),
                    'contains_credentials': http.contains_credentials,
                })

    def export_iocs(self, result: AnalysisResult, output_path: Path | str) -> None:
        """Export all IOCs to CSV."""
        headers = ['type', 'value', 'source', 'is_matched', 'severity', 'context']

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers, delimiter=self.delimiter, quoting=self.quoting)
            writer.writeheader()

            # Extracted IPs
            for ip in sorted(result.extracted_ips):
                matched = any(m.ioc_value == ip for m in result.ioc_matches)
                writer.writerow({
                    'type': 'ip_address',
                    'value': ip,
                    'source': 'extracted',
                    'is_matched': matched,
                    'severity': '',
                    'context': '',
                })

            # Extracted domains
            for domain in sorted(result.extracted_domains):
                matched = any(m.ioc_value == domain for m in result.ioc_matches)
                writer.writerow({
                    'type': 'domain',
                    'value': domain,
                    'source': 'extracted',
                    'is_matched': matched,
                    'severity': '',
                    'context': '',
                })

            # Extracted URLs
            for url in sorted(result.extracted_urls):
                writer.writerow({
                    'type': 'url',
                    'value': url,
                    'source': 'extracted',
                    'is_matched': False,
                    'severity': '',
                    'context': '',
                })

            # JA3 hashes
            for ja3 in sorted(result.extracted_ja3_hashes):
                writer.writerow({
                    'type': 'ja3',
                    'value': ja3,
                    'source': 'extracted',
                    'is_matched': False,
                    'severity': '',
                    'context': '',
                })

            # IOC matches
            for match in result.ioc_matches:
                writer.writerow({
                    'type': match.ioc_type.value,
                    'value': match.ioc_value,
                    'source': 'matched',
                    'is_matched': True,
                    'severity': match.severity.value,
                    'context': match.context or '',
                })

    def export_threats(self, result: AnalysisResult, output_path: Path | str) -> None:
        """Export suspicious activities and threats to CSV."""
        headers = [
            'timestamp', 'type', 'severity', 'description',
            'src_ip', 'dst_ip', 'port', 'protocol',
            'mitre_tactics', 'mitre_techniques', 'evidence',
        ]

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers, delimiter=self.delimiter, quoting=self.quoting)
            writer.writeheader()

            for activity in result.suspicious_activities:
                writer.writerow({
                    'timestamp': activity.timestamp.isoformat() if activity.timestamp else '',
                    'type': activity.activity_type,
                    'severity': activity.severity.value,
                    'description': activity.description,
                    'src_ip': activity.src_ip or '',
                    'dst_ip': activity.dst_ip or '',
                    'port': activity.port or '',
                    'protocol': activity.protocol.value if activity.protocol else '',
                    'mitre_tactics': ';'.join(activity.mitre_tactics),
                    'mitre_techniques': ';'.join(activity.mitre_techniques),
                    'evidence': ';'.join(activity.evidence),
                })

            # Add beacon detections
            for beacon in result.beacon_patterns:
                if beacon.is_likely_beacon:
                    writer.writerow({
                        'timestamp': beacon.first_seen.isoformat(),
                        'type': 'beacon_pattern',
                        'severity': 'high',
                        'description': f'Beaconing detected: interval={beacon.interval_mean:.1f}s, jitter={beacon.jitter_percent:.1f}%',
                        'src_ip': '',
                        'dst_ip': beacon.dst_ip,
                        'port': beacon.dst_port,
                        'protocol': '',
                        'mitre_tactics': 'Command and Control',
                        'mitre_techniques': 'T1071',
                        'evidence': f'Connections: {beacon.connection_count}, Confidence: {beacon.confidence:.0%}',
                    })

            # Add exfiltration suspects
            for exfil in result.exfiltration_suspects:
                writer.writerow({
                    'timestamp': exfil.timestamp.isoformat() if exfil.timestamp else '',
                    'type': 'data_exfiltration',
                    'severity': 'high',
                    'description': f'Possible data exfiltration: {exfil.bytes_sent} bytes sent',
                    'src_ip': '',
                    'dst_ip': exfil.dst_ip,
                    'port': exfil.dst_port,
                    'protocol': exfil.protocol.value,
                    'mitre_tactics': 'Exfiltration',
                    'mitre_techniques': 'T1041',
                    'evidence': ';'.join(exfil.suspicion_reasons),
                })

    def export_files(self, result: AnalysisResult, output_path: Path | str) -> None:
        """Export extracted files to CSV."""
        headers = [
            'filename', 'size', 'content_type', 'magic_type',
            'md5', 'sha1', 'sha256', 'entropy',
            'is_executable', 'is_suspicious', 'suspicion_reasons', 'yara_matches',
        ]

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers, delimiter=self.delimiter, quoting=self.quoting)
            writer.writeheader()

            for file in result.files:
                writer.writerow({
                    'filename': file.filename or '',
                    'size': file.size,
                    'content_type': file.content_type or '',
                    'magic_type': file.magic_type or '',
                    'md5': file.md5 or '',
                    'sha1': file.sha1 or '',
                    'sha256': file.sha256 or '',
                    'entropy': f'{file.entropy:.4f}' if file.entropy else '',
                    'is_executable': file.is_executable,
                    'is_suspicious': file.is_suspicious,
                    'suspicion_reasons': ';'.join(file.suspicion_reasons),
                    'yara_matches': ';'.join(file.yara_matches),
                })

    def export_credentials(self, result: AnalysisResult, output_path: Path | str) -> None:
        """Export extracted credentials to CSV (passwords redacted)."""
        headers = [
            'timestamp', 'protocol', 'src_ip', 'dst_ip', 'url',
            'username', 'domain', 'is_cleartext', 'hash_type',
        ]

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers, delimiter=self.delimiter, quoting=self.quoting)
            writer.writeheader()

            for cred in result.credentials:
                writer.writerow({
                    'timestamp': cred.timestamp.isoformat() if cred.timestamp else '',
                    'protocol': cred.protocol.value,
                    'src_ip': cred.src_ip or '',
                    'dst_ip': cred.dst_ip or '',
                    'url': cred.url or '',
                    'username': cred.username or '',
                    'domain': cred.domain or '',
                    'is_cleartext': cred.is_cleartext,
                    'hash_type': cred.hash_type or '',
                })
