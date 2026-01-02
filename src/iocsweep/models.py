"""
Data models for IOCSweep intelligence extraction.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(Enum):
    """Threat severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCType(Enum):
    """Types of Indicators of Compromise."""

    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    JA3 = "ja3"
    JA3S = "ja3s"
    JARM = "jarm"
    USER_AGENT = "user_agent"
    SSL_CERT_HASH = "ssl_cert_hash"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry_key"


class Protocol(Enum):
    """Network protocols."""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    SMTP = "SMTP"
    FTP = "FTP"
    SSH = "SSH"
    TELNET = "TELNET"
    SMB = "SMB"
    RDP = "RDP"
    IRC = "IRC"
    TOR = "TOR"
    UNKNOWN = "UNKNOWN"


@dataclass
class GeoLocation:
    """Geographic location data."""

    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    region: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    asn_org: str | None = None
    isp: str | None = None


@dataclass
class NetworkConnection:
    """Represents a network connection/flow."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    first_seen: datetime
    last_seen: datetime
    packet_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    src_geo: GeoLocation | None = None
    dst_geo: GeoLocation | None = None
    flags: list[str] = field(default_factory=list)
    is_established: bool = False
    duration_seconds: float = 0.0

    @property
    def flow_id(self) -> str:
        """Generate unique flow identifier."""
        return hashlib.md5(
            f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol.value}".encode()
        ).hexdigest()[:16]


@dataclass
class DNSRecord:
    """DNS query/response data."""

    query_name: str
    query_type: str
    response_data: list[str] = field(default_factory=list)
    ttl: int | None = None
    timestamp: datetime | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    is_nx_domain: bool = False
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)
    entropy: float | None = None


@dataclass
class HTTPTransaction:
    """HTTP request/response pair."""

    method: str
    host: str
    uri: str
    user_agent: str | None = None
    referer: str | None = None
    content_type: str | None = None
    status_code: int | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    request_body: bytes | None = None
    response_body: bytes | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    timestamp: datetime | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    contains_credentials: bool = False
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)

    @property
    def full_url(self) -> str:
        """Get full URL."""
        return f"http://{self.host}{self.uri}"


@dataclass
class TLSSession:
    """TLS/SSL session data."""

    server_name: str | None = None
    ja3_hash: str | None = None
    ja3s_hash: str | None = None
    ja3_full: str | None = None
    ja3s_full: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    certificate_chain: list[dict[str, Any]] = field(default_factory=list)
    certificate_issuer: str | None = None
    certificate_subject: str | None = None
    certificate_serial: str | None = None
    certificate_not_before: datetime | None = None
    certificate_not_after: datetime | None = None
    certificate_sha256: str | None = None
    is_self_signed: bool = False
    is_expired: bool = False
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)
    timestamp: datetime | None = None
    src_ip: str | None = None
    dst_ip: str | None = None


@dataclass
class FileExtraction:
    """Extracted file from network traffic."""

    filename: str | None = None
    content_type: str | None = None
    magic_type: str | None = None
    size: int = 0
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    ssdeep: str | None = None
    entropy: float | None = None
    data: bytes | None = None
    source_protocol: Protocol = Protocol.UNKNOWN
    src_ip: str | None = None
    dst_ip: str | None = None
    timestamp: datetime | None = None
    is_executable: bool = False
    is_archive: bool = False
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)
    yara_matches: list[str] = field(default_factory=list)


@dataclass
class Credential:
    """Extracted credential data."""

    username: str | None = None
    password: str | None = None
    password_hash: str | None = None
    hash_type: str | None = None
    domain: str | None = None
    protocol: Protocol = Protocol.UNKNOWN
    src_ip: str | None = None
    dst_ip: str | None = None
    url: str | None = None
    timestamp: datetime | None = None
    is_cleartext: bool = False


@dataclass
class IOCMatch:
    """IOC match result."""

    ioc_value: str
    ioc_type: IOCType
    matched_in: str  # Where it was found (packet, dns, http, etc.)
    context: str | None = None
    packet_number: int | None = None
    timestamp: datetime | None = None
    severity: Severity = Severity.MEDIUM
    src_ip: str | None = None
    dst_ip: str | None = None
    additional_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class BeaconPattern:
    """Detected beaconing behavior."""

    dst_ip: str
    dst_port: int
    interval_mean: float
    interval_stddev: float
    jitter_percent: float
    connection_count: int
    first_seen: datetime
    last_seen: datetime
    is_likely_beacon: bool = False
    confidence: float = 0.0


@dataclass
class DataExfiltration:
    """Potential data exfiltration detection."""

    dst_ip: str
    dst_port: int
    bytes_sent: int
    bytes_received: int
    ratio: float
    protocol: Protocol
    entropy: float | None = None
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)
    timestamp: datetime | None = None


@dataclass
class SuspiciousActivity:
    """Generic suspicious activity detection."""

    activity_type: str
    description: str
    severity: Severity
    src_ip: str | None = None
    dst_ip: str | None = None
    port: int | None = None
    protocol: Protocol | None = None
    evidence: list[str] = field(default_factory=list)
    timestamp: datetime | None = None
    packet_numbers: list[int] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Complete analysis result."""

    pcap_file: str
    start_time: datetime
    end_time: datetime
    total_packets: int
    total_bytes: int
    analysis_duration_seconds: float

    # Network intelligence
    connections: list[NetworkConnection] = field(default_factory=list)
    unique_src_ips: set[str] = field(default_factory=set)
    unique_dst_ips: set[str] = field(default_factory=set)
    unique_domains: set[str] = field(default_factory=set)

    # Protocol-specific data
    dns_records: list[DNSRecord] = field(default_factory=list)
    http_transactions: list[HTTPTransaction] = field(default_factory=list)
    tls_sessions: list[TLSSession] = field(default_factory=list)

    # Extracted artifacts
    files: list[FileExtraction] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)

    # IOC matches
    ioc_matches: list[IOCMatch] = field(default_factory=list)

    # Behavioral analysis
    beacon_patterns: list[BeaconPattern] = field(default_factory=list)
    exfiltration_suspects: list[DataExfiltration] = field(default_factory=list)
    suspicious_activities: list[SuspiciousActivity] = field(default_factory=list)

    # Extracted IOCs (auto-discovered)
    extracted_ips: set[str] = field(default_factory=set)
    extracted_domains: set[str] = field(default_factory=set)
    extracted_urls: set[str] = field(default_factory=set)
    extracted_emails: set[str] = field(default_factory=set)
    extracted_hashes: dict[str, set[str]] = field(default_factory=dict)
    extracted_ja3_hashes: set[str] = field(default_factory=set)
    extracted_user_agents: set[str] = field(default_factory=set)

    # Statistics
    protocol_distribution: dict[str, int] = field(default_factory=dict)
    port_distribution: dict[int, int] = field(default_factory=dict)
    top_talkers: list[tuple[str, int]] = field(default_factory=list)
    geolocation_summary: dict[str, int] = field(default_factory=dict)

    def get_severity_counts(self) -> dict[Severity, int]:
        """Count findings by severity."""
        counts = {s: 0 for s in Severity}
        for activity in self.suspicious_activities:
            counts[activity.severity] += 1
        for ioc in self.ioc_matches:
            counts[ioc.severity] += 1
        return counts

    def get_critical_findings(self) -> list[SuspiciousActivity | IOCMatch]:
        """Get all critical and high severity findings."""
        findings: list[SuspiciousActivity | IOCMatch] = []
        findings.extend(
            [a for a in self.suspicious_activities if a.severity in (Severity.CRITICAL, Severity.HIGH)]
        )
        findings.extend(
            [i for i in self.ioc_matches if i.severity in (Severity.CRITICAL, Severity.HIGH)]
        )
        return findings
