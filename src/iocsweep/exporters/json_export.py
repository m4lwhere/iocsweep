"""
JSON export for IOCSweep analysis results.

Exports analysis results in a structured JSON format suitable for:
- SIEM ingestion
- Threat intelligence platforms
- Automated processing
- Long-term storage
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

try:
    import orjson

    def json_dumps(obj: Any, pretty: bool = False) -> str:
        opts = orjson.OPT_SORT_KEYS
        if pretty:
            opts |= orjson.OPT_INDENT_2
        return orjson.dumps(obj, option=opts, default=_json_serializer).decode()
except ImportError:
    import json

    def json_dumps(obj: Any, pretty: bool = False) -> str:
        return json.dumps(obj, default=_json_serializer, indent=2 if pretty else None, sort_keys=True)

from iocsweep.models import AnalysisResult


def _json_serializer(obj: Any) -> Any:
    """Custom JSON serializer for complex types."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, set):
        return sorted(list(obj))
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, Path):
        return str(obj)
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


class JSONExporter:
    """
    Export analysis results to JSON format.

    Supports:
    - Full detailed export
    - IOC-only export
    - Summary export
    - MISP-compatible format
    """

    def __init__(self, pretty: bool = True):
        """
        Initialize JSON exporter.

        Args:
            pretty: Whether to format output with indentation
        """
        self.pretty = pretty

    def export(self, result: AnalysisResult, output_path: Path | str) -> None:
        """
        Export full analysis result to JSON file.

        Args:
            result: Analysis result to export
            output_path: Path to output file
        """
        data = self._result_to_dict(result)
        json_str = json_dumps(data, pretty=self.pretty)

        with open(output_path, 'w') as f:
            f.write(json_str)

    def export_string(self, result: AnalysisResult) -> str:
        """
        Export analysis result to JSON string.

        Args:
            result: Analysis result to export

        Returns:
            JSON string
        """
        data = self._result_to_dict(result)
        return json_dumps(data, pretty=self.pretty)

    def export_iocs_only(self, result: AnalysisResult, output_path: Path | str) -> None:
        """
        Export only IOCs to JSON file.

        Args:
            result: Analysis result
            output_path: Path to output file
        """
        iocs = {
            'extracted_at': datetime.now().isoformat(),
            'source_file': result.pcap_file,
            'iocs': {
                'ip_addresses': sorted(result.extracted_ips),
                'domains': sorted(result.extracted_domains),
                'urls': sorted(result.extracted_urls),
                'emails': sorted(result.extracted_emails),
                'ja3_hashes': sorted(result.extracted_ja3_hashes),
                'user_agents': sorted(result.extracted_user_agents),
                'file_hashes': {
                    hash_type: sorted(hashes)
                    for hash_type, hashes in result.extracted_hashes.items()
                },
            },
            'ioc_matches': [
                {
                    'value': m.ioc_value,
                    'type': m.ioc_type.value,
                    'severity': m.severity.value,
                    'context': m.context,
                    'timestamp': m.timestamp.isoformat() if m.timestamp else None,
                }
                for m in result.ioc_matches
            ],
        }

        json_str = json_dumps(iocs, pretty=self.pretty)
        with open(output_path, 'w') as f:
            f.write(json_str)

    def export_summary(self, result: AnalysisResult, output_path: Path | str) -> None:
        """
        Export summary statistics to JSON file.

        Args:
            result: Analysis result
            output_path: Path to output file
        """
        severity_counts = result.get_severity_counts()

        summary = {
            'metadata': {
                'pcap_file': result.pcap_file,
                'analysis_start': result.start_time.isoformat(),
                'analysis_end': result.end_time.isoformat(),
                'duration_seconds': result.analysis_duration_seconds,
            },
            'statistics': {
                'total_packets': result.total_packets,
                'total_bytes': result.total_bytes,
                'unique_source_ips': len(result.unique_src_ips),
                'unique_destination_ips': len(result.unique_dst_ips),
                'unique_domains': len(result.unique_domains),
                'total_connections': len(result.connections),
                'dns_queries': len(result.dns_records),
                'http_transactions': len(result.http_transactions),
                'tls_sessions': len(result.tls_sessions),
                'extracted_files': len(result.files),
                'extracted_credentials': len(result.credentials),
            },
            'threat_summary': {
                'ioc_matches': len(result.ioc_matches),
                'suspicious_activities': len(result.suspicious_activities),
                'beacon_patterns': len([b for b in result.beacon_patterns if b.is_likely_beacon]),
                'exfiltration_suspects': len(result.exfiltration_suspects),
                'severity_breakdown': {s.value: c for s, c in severity_counts.items()},
            },
            'protocol_distribution': result.protocol_distribution,
            'top_ports': dict(sorted(
                result.port_distribution.items(),
                key=lambda x: x[1],
                reverse=True
            )[:20]),
            'top_talkers': result.top_talkers[:10],
            'geolocation_summary': result.geolocation_summary,
        }

        json_str = json_dumps(summary, pretty=self.pretty)
        with open(output_path, 'w') as f:
            f.write(json_str)

    def _result_to_dict(self, result: AnalysisResult) -> dict:
        """Convert AnalysisResult to dictionary."""
        return {
            'metadata': {
                'tool': 'IOCSweep',
                'version': '2.0.0',
                'export_time': datetime.now().isoformat(),
                'pcap_file': result.pcap_file,
                'analysis_start': result.start_time.isoformat(),
                'analysis_end': result.end_time.isoformat(),
                'duration_seconds': result.analysis_duration_seconds,
            },
            'statistics': {
                'total_packets': result.total_packets,
                'total_bytes': result.total_bytes,
                'protocol_distribution': result.protocol_distribution,
                'port_distribution': dict(sorted(
                    result.port_distribution.items(),
                    key=lambda x: x[1],
                    reverse=True
                )),
                'top_talkers': result.top_talkers,
                'geolocation_summary': result.geolocation_summary,
            },
            'network': {
                'connections': [self._connection_to_dict(c) for c in result.connections],
                'unique_source_ips': sorted(result.unique_src_ips),
                'unique_destination_ips': sorted(result.unique_dst_ips),
                'unique_domains': sorted(result.unique_domains),
            },
            'dns': [self._dns_to_dict(d) for d in result.dns_records],
            'http': [self._http_to_dict(h) for h in result.http_transactions],
            'tls': [self._tls_to_dict(t) for t in result.tls_sessions],
            'extracted_files': [self._file_to_dict(f) for f in result.files],
            'credentials': [self._cred_to_dict(c) for c in result.credentials],
            'iocs': {
                'extracted': {
                    'ip_addresses': sorted(result.extracted_ips),
                    'domains': sorted(result.extracted_domains),
                    'urls': sorted(result.extracted_urls),
                    'emails': sorted(result.extracted_emails),
                    'ja3_hashes': sorted(result.extracted_ja3_hashes),
                    'user_agents': sorted(result.extracted_user_agents),
                },
                'matches': [self._ioc_match_to_dict(m) for m in result.ioc_matches],
            },
            'threats': {
                'beacon_patterns': [self._beacon_to_dict(b) for b in result.beacon_patterns],
                'exfiltration_suspects': [self._exfil_to_dict(e) for e in result.exfiltration_suspects],
                'suspicious_activities': [self._activity_to_dict(a) for a in result.suspicious_activities],
            },
        }

    def _connection_to_dict(self, conn) -> dict:
        """Convert connection to dict."""
        return {
            'src_ip': conn.src_ip,
            'dst_ip': conn.dst_ip,
            'src_port': conn.src_port,
            'dst_port': conn.dst_port,
            'protocol': conn.protocol.value,
            'first_seen': conn.first_seen.isoformat(),
            'last_seen': conn.last_seen.isoformat(),
            'packet_count': conn.packet_count,
            'bytes_sent': conn.bytes_sent,
            'bytes_received': conn.bytes_received,
            'duration_seconds': conn.duration_seconds,
            'src_geo': asdict(conn.src_geo) if conn.src_geo else None,
            'dst_geo': asdict(conn.dst_geo) if conn.dst_geo else None,
        }

    def _dns_to_dict(self, dns) -> dict:
        """Convert DNS record to dict."""
        return {
            'query_name': dns.query_name,
            'query_type': dns.query_type,
            'response_data': dns.response_data,
            'ttl': dns.ttl,
            'timestamp': dns.timestamp.isoformat() if dns.timestamp else None,
            'src_ip': dns.src_ip,
            'dst_ip': dns.dst_ip,
            'is_suspicious': dns.is_suspicious,
            'suspicion_reasons': dns.suspicion_reasons,
            'entropy': dns.entropy,
        }

    def _http_to_dict(self, http) -> dict:
        """Convert HTTP transaction to dict."""
        return {
            'method': http.method,
            'host': http.host,
            'uri': http.uri,
            'full_url': http.full_url,
            'user_agent': http.user_agent,
            'referer': http.referer,
            'content_type': http.content_type,
            'status_code': http.status_code,
            'timestamp': http.timestamp.isoformat() if http.timestamp else None,
            'src_ip': http.src_ip,
            'dst_ip': http.dst_ip,
            'is_suspicious': http.is_suspicious,
            'suspicion_reasons': http.suspicion_reasons,
            'contains_credentials': http.contains_credentials,
        }

    def _tls_to_dict(self, tls) -> dict:
        """Convert TLS session to dict."""
        return {
            'server_name': tls.server_name,
            'ja3_hash': tls.ja3_hash,
            'ja3s_hash': tls.ja3s_hash,
            'tls_version': tls.tls_version,
            'cipher_suite': tls.cipher_suite,
            'certificate_sha256': tls.certificate_sha256,
            'is_self_signed': tls.is_self_signed,
            'is_expired': tls.is_expired,
            'is_suspicious': tls.is_suspicious,
            'suspicion_reasons': tls.suspicion_reasons,
            'timestamp': tls.timestamp.isoformat() if tls.timestamp else None,
            'src_ip': tls.src_ip,
            'dst_ip': tls.dst_ip,
        }

    def _file_to_dict(self, file) -> dict:
        """Convert file extraction to dict."""
        return {
            'filename': file.filename,
            'content_type': file.content_type,
            'magic_type': file.magic_type,
            'size': file.size,
            'md5': file.md5,
            'sha1': file.sha1,
            'sha256': file.sha256,
            'entropy': file.entropy,
            'is_executable': file.is_executable,
            'is_archive': file.is_archive,
            'is_suspicious': file.is_suspicious,
            'suspicion_reasons': file.suspicion_reasons,
            'yara_matches': file.yara_matches,
            'source_protocol': file.source_protocol.value,
        }

    def _cred_to_dict(self, cred) -> dict:
        """Convert credential to dict."""
        return {
            'username': cred.username,
            'password': '***REDACTED***' if cred.password else None,
            'domain': cred.domain,
            'protocol': cred.protocol.value,
            'url': cred.url,
            'is_cleartext': cred.is_cleartext,
            'timestamp': cred.timestamp.isoformat() if cred.timestamp else None,
            'src_ip': cred.src_ip,
            'dst_ip': cred.dst_ip,
        }

    def _ioc_match_to_dict(self, match) -> dict:
        """Convert IOC match to dict."""
        return {
            'value': match.ioc_value,
            'type': match.ioc_type.value,
            'matched_in': match.matched_in,
            'context': match.context,
            'severity': match.severity.value,
            'packet_number': match.packet_number,
            'timestamp': match.timestamp.isoformat() if match.timestamp else None,
            'src_ip': match.src_ip,
            'dst_ip': match.dst_ip,
        }

    def _beacon_to_dict(self, beacon) -> dict:
        """Convert beacon pattern to dict."""
        return {
            'dst_ip': beacon.dst_ip,
            'dst_port': beacon.dst_port,
            'interval_mean': beacon.interval_mean,
            'interval_stddev': beacon.interval_stddev,
            'jitter_percent': beacon.jitter_percent,
            'connection_count': beacon.connection_count,
            'first_seen': beacon.first_seen.isoformat(),
            'last_seen': beacon.last_seen.isoformat(),
            'is_likely_beacon': beacon.is_likely_beacon,
            'confidence': beacon.confidence,
        }

    def _exfil_to_dict(self, exfil) -> dict:
        """Convert exfiltration suspect to dict."""
        return {
            'dst_ip': exfil.dst_ip,
            'dst_port': exfil.dst_port,
            'bytes_sent': exfil.bytes_sent,
            'bytes_received': exfil.bytes_received,
            'ratio': exfil.ratio if exfil.ratio != float('inf') else 'infinity',
            'protocol': exfil.protocol.value,
            'entropy': exfil.entropy,
            'suspicion_reasons': exfil.suspicion_reasons,
        }

    def _activity_to_dict(self, activity) -> dict:
        """Convert suspicious activity to dict."""
        return {
            'type': activity.activity_type,
            'description': activity.description,
            'severity': activity.severity.value,
            'src_ip': activity.src_ip,
            'dst_ip': activity.dst_ip,
            'port': activity.port,
            'protocol': activity.protocol.value if activity.protocol else None,
            'evidence': activity.evidence,
            'mitre_tactics': activity.mitre_tactics,
            'mitre_techniques': activity.mitre_techniques,
            'timestamp': activity.timestamp.isoformat() if activity.timestamp else None,
        }
