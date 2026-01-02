"""
Core IOCSweep analysis engine.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from scapy.all import (
    DNS,
    DNSQR,
    DNSRR,
    IP,
    TCP,
    UDP,
    ICMP,
    Raw,
    PcapReader,
    rdpcap,
    conf,
)

from iocsweep.models import (
    AnalysisResult,
    BeaconPattern,
    Credential,
    DataExfiltration,
    DNSRecord,
    FileExtraction,
    GeoLocation,
    HTTPTransaction,
    IOCMatch,
    IOCType,
    NetworkConnection,
    Protocol,
    Severity,
    SuspiciousActivity,
    TLSSession,
)
from iocsweep.analyzers.dns import DNSAnalyzer
from iocsweep.analyzers.http import HTTPAnalyzer
from iocsweep.analyzers.tls import TLSAnalyzer
from iocsweep.analyzers.beacon import BeaconAnalyzer
from iocsweep.analyzers.exfil import ExfilAnalyzer
from iocsweep.extractors.ioc import IOCExtractor
from iocsweep.extractors.files import FileExtractor
from iocsweep.extractors.credentials import CredentialExtractor
from iocsweep.utils.geo import GeoLookup
from iocsweep.utils.entropy import calculate_entropy

# Suppress scapy warnings
conf.verb = 0


class IOCSweep:
    """
    Advanced PCAP Intelligence Extraction Engine.

    Extracts maximum intel value from network packet captures.
    """

    def __init__(
        self,
        ioc_file: str | Path | None = None,
        enable_geo: bool = True,
        enable_file_extraction: bool = True,
        enable_credential_extraction: bool = True,
        enable_beacon_detection: bool = True,
        enable_exfil_detection: bool = True,
        yara_rules_path: str | Path | None = None,
        maxmind_db_path: str | Path | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ):
        """
        Initialize IOCSweep analyzer.

        Args:
            ioc_file: Path to IOC file for matching
            enable_geo: Enable geolocation lookups
            enable_file_extraction: Enable file carving from traffic
            enable_credential_extraction: Enable credential extraction
            enable_beacon_detection: Enable beacon pattern detection
            enable_exfil_detection: Enable data exfiltration detection
            yara_rules_path: Path to YARA rules for file scanning
            maxmind_db_path: Path to MaxMind GeoIP database
            progress_callback: Callback for progress updates (current, total)
        """
        self.ioc_file = Path(ioc_file) if ioc_file else None
        self.enable_geo = enable_geo
        self.enable_file_extraction = enable_file_extraction
        self.enable_credential_extraction = enable_credential_extraction
        self.enable_beacon_detection = enable_beacon_detection
        self.enable_exfil_detection = enable_exfil_detection
        self.yara_rules_path = Path(yara_rules_path) if yara_rules_path else None
        self.progress_callback = progress_callback

        # Initialize analyzers
        self.dns_analyzer = DNSAnalyzer()
        self.http_analyzer = HTTPAnalyzer()
        self.tls_analyzer = TLSAnalyzer()
        self.beacon_analyzer = BeaconAnalyzer()
        self.exfil_analyzer = ExfilAnalyzer()

        # Initialize extractors
        self.ioc_extractor = IOCExtractor()
        self.file_extractor = FileExtractor(yara_rules_path=yara_rules_path)
        self.credential_extractor = CredentialExtractor()

        # Initialize geo lookup
        self.geo_lookup = GeoLookup(maxmind_db_path) if enable_geo else None

        # Load IOCs if provided
        self.iocs: dict[IOCType, set[str]] = defaultdict(set)
        if self.ioc_file:
            self._load_iocs()

    def _load_iocs(self) -> None:
        """Load IOCs from file."""
        if not self.ioc_file or not self.ioc_file.exists():
            return

        with open(self.ioc_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Auto-detect IOC type
                ioc_type = self.ioc_extractor.detect_ioc_type(line)
                if ioc_type:
                    self.iocs[ioc_type].add(line.lower())

    def analyze(self, pcap_path: str | Path) -> AnalysisResult:
        """
        Perform comprehensive PCAP analysis.

        Args:
            pcap_path: Path to PCAP file

        Returns:
            AnalysisResult with all extracted intelligence
        """
        pcap_path = Path(pcap_path)
        start_time = datetime.now()

        # Initialize result
        result = AnalysisResult(
            pcap_file=str(pcap_path),
            start_time=start_time,
            end_time=start_time,
            total_packets=0,
            total_bytes=0,
            analysis_duration_seconds=0.0,
        )

        # Connection tracking
        connections: dict[str, NetworkConnection] = {}
        flow_packets: dict[str, list[Any]] = defaultdict(list)
        connection_times: dict[str, list[datetime]] = defaultdict(list)

        # Stream reassembly buffers
        tcp_streams: dict[str, bytes] = defaultdict(bytes)

        # Get file size for progress
        file_size = pcap_path.stat().st_size
        bytes_read = 0

        # Process packets
        packet_num = 0
        for packet in PcapReader(str(pcap_path)):
            packet_num += 1
            result.total_packets += 1
            pkt_len = len(packet)
            result.total_bytes += pkt_len
            bytes_read += pkt_len

            # Progress callback
            if self.progress_callback and packet_num % 1000 == 0:
                self.progress_callback(bytes_read, file_size)

            # Get timestamp
            pkt_time = datetime.fromtimestamp(float(packet.time))

            # Process IP layer
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                result.extracted_ips.add(src_ip)
                result.extracted_ips.add(dst_ip)
                result.unique_src_ips.add(src_ip)
                result.unique_dst_ips.add(dst_ip)

                # Check IOCs
                self._check_ip_iocs(src_ip, dst_ip, packet_num, pkt_time, result)

                # Determine protocol and ports
                protocol = Protocol.UNKNOWN
                src_port = 0
                dst_port = 0

                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    protocol = self._get_protocol_from_port(dst_port, "tcp")

                    # Track TCP flags
                    flags = self._get_tcp_flags(tcp_layer)

                    # Create flow key
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    reverse_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"

                    # Use existing flow or create new
                    active_key = flow_key if flow_key in connections else (
                        reverse_key if reverse_key in connections else flow_key
                    )

                    if active_key not in connections:
                        connections[active_key] = NetworkConnection(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=protocol,
                            first_seen=pkt_time,
                            last_seen=pkt_time,
                        )

                    conn = connections[active_key]
                    conn.last_seen = pkt_time
                    conn.packet_count += 1
                    conn.flags.extend(flags)

                    if active_key == flow_key:
                        conn.bytes_sent += pkt_len
                    else:
                        conn.bytes_received += pkt_len

                    # Track for beacon detection
                    connection_times[f"{dst_ip}:{dst_port}"].append(pkt_time)

                    # Store packets for stream reassembly
                    flow_packets[active_key].append(packet)

                    # Reassemble TCP streams for protocol analysis
                    if packet.haslayer(Raw):
                        payload = bytes(packet[Raw].load)
                        tcp_streams[active_key] += payload

                        # Check for HTTP
                        if self._is_http(payload):
                            http_trans = self.http_analyzer.parse_transaction(
                                payload, src_ip, dst_ip, pkt_time
                            )
                            if http_trans:
                                result.http_transactions.append(http_trans)
                                if http_trans.user_agent:
                                    result.extracted_user_agents.add(http_trans.user_agent)
                                result.extracted_urls.add(http_trans.full_url)
                                result.extracted_domains.add(http_trans.host)

                                # Extract IOCs from HTTP
                                self._extract_http_iocs(http_trans, result)

                        # Check for credentials
                        if self.enable_credential_extraction:
                            creds = self.credential_extractor.extract_from_payload(
                                payload, protocol, src_ip, dst_ip, pkt_time
                            )
                            result.credentials.extend(creds)

                    # Check for TLS
                    if dst_port == 443 or src_port == 443:
                        if packet.haslayer(Raw):
                            tls_info = self.tls_analyzer.parse_handshake(
                                bytes(packet[Raw].load), src_ip, dst_ip, pkt_time
                            )
                            if tls_info:
                                result.tls_sessions.append(tls_info)
                                if tls_info.ja3_hash:
                                    result.extracted_ja3_hashes.add(tls_info.ja3_hash)
                                if tls_info.server_name:
                                    result.extracted_domains.add(tls_info.server_name)

                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    protocol = self._get_protocol_from_port(dst_port, "udp")

                    # Create connection entry
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    if flow_key not in connections:
                        connections[flow_key] = NetworkConnection(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=protocol,
                            first_seen=pkt_time,
                            last_seen=pkt_time,
                        )
                    connections[flow_key].packet_count += 1
                    connections[flow_key].bytes_sent += pkt_len

                elif packet.haslayer(ICMP):
                    protocol = Protocol.ICMP
                    flow_key = f"{src_ip}-{dst_ip}-ICMP"
                    if flow_key not in connections:
                        connections[flow_key] = NetworkConnection(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=0,
                            dst_port=0,
                            protocol=protocol,
                            first_seen=pkt_time,
                            last_seen=pkt_time,
                        )
                    connections[flow_key].packet_count += 1

                # Update port distribution
                if dst_port > 0:
                    result.port_distribution[dst_port] = result.port_distribution.get(dst_port, 0) + 1

                # Update protocol distribution
                result.protocol_distribution[protocol.value] = (
                    result.protocol_distribution.get(protocol.value, 0) + 1
                )

            # Process DNS
            if packet.haslayer(DNS):
                dns_records = self.dns_analyzer.parse_packet(packet, pkt_time)
                for record in dns_records:
                    result.dns_records.append(record)
                    result.extracted_domains.add(record.query_name.rstrip('.'))
                    result.unique_domains.add(record.query_name.rstrip('.'))

                    # Check DNS against IOCs
                    self._check_domain_iocs(record.query_name, packet_num, pkt_time, result)

        # Post-processing

        # Add connections to result
        result.connections = list(connections.values())

        # Calculate connection durations
        for conn in result.connections:
            conn.duration_seconds = (conn.last_seen - conn.first_seen).total_seconds()

        # Geolocation lookups
        if self.enable_geo and self.geo_lookup:
            self._enrich_with_geo(result)

        # Beacon detection
        if self.enable_beacon_detection:
            result.beacon_patterns = self.beacon_analyzer.detect_beacons(connection_times)

        # Exfiltration detection
        if self.enable_exfil_detection:
            result.exfiltration_suspects = self.exfil_analyzer.detect_exfil(result.connections)

        # File extraction from streams
        if self.enable_file_extraction:
            for stream_key, stream_data in tcp_streams.items():
                files = self.file_extractor.extract_from_stream(stream_data)
                result.files.extend(files)

        # Calculate top talkers
        ip_bytes: dict[str, int] = defaultdict(int)
        for conn in result.connections:
            ip_bytes[conn.src_ip] += conn.bytes_sent
            ip_bytes[conn.dst_ip] += conn.bytes_received
        result.top_talkers = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:20]

        # Detect suspicious activities
        self._detect_suspicious_activities(result)

        # Finalize
        end_time = datetime.now()
        result.end_time = end_time
        result.analysis_duration_seconds = (end_time - start_time).total_seconds()

        return result

    def _get_protocol_from_port(self, port: int, transport: str) -> Protocol:
        """Determine application protocol from port number."""
        tcp_ports = {
            80: Protocol.HTTP,
            443: Protocol.HTTPS,
            22: Protocol.SSH,
            23: Protocol.TELNET,
            25: Protocol.SMTP,
            21: Protocol.FTP,
            445: Protocol.SMB,
            3389: Protocol.RDP,
            6667: Protocol.IRC,
            6668: Protocol.IRC,
            6669: Protocol.IRC,
            9001: Protocol.TOR,
            9050: Protocol.TOR,
        }
        udp_ports = {
            53: Protocol.DNS,
        }

        if transport == "tcp":
            return tcp_ports.get(port, Protocol.TCP)
        elif transport == "udp":
            return udp_ports.get(port, Protocol.UDP)
        return Protocol.UNKNOWN

    def _get_tcp_flags(self, tcp_layer: TCP) -> list[str]:
        """Extract TCP flags."""
        flags = []
        flag_map = {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR',
        }
        for flag_char, flag_name in flag_map.items():
            if flag_char in str(tcp_layer.flags):
                flags.append(flag_name)
        return flags

    def _is_http(self, payload: bytes) -> bool:
        """Check if payload is HTTP."""
        http_methods = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ', b'PATCH ']
        http_response = b'HTTP/'
        return any(payload.startswith(m) for m in http_methods) or payload.startswith(http_response)

    def _check_ip_iocs(
        self,
        src_ip: str,
        dst_ip: str,
        packet_num: int,
        pkt_time: datetime,
        result: AnalysisResult,
    ) -> None:
        """Check IPs against IOC list."""
        for ip in [src_ip, dst_ip]:
            if ip.lower() in self.iocs[IOCType.IP_ADDRESS]:
                match = IOCMatch(
                    ioc_value=ip,
                    ioc_type=IOCType.IP_ADDRESS,
                    matched_in="packet",
                    packet_number=packet_num,
                    timestamp=pkt_time,
                    severity=Severity.HIGH,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                )
                # Avoid duplicates
                if not any(m.ioc_value == ip for m in result.ioc_matches):
                    result.ioc_matches.append(match)

    def _check_domain_iocs(
        self,
        domain: str,
        packet_num: int,
        pkt_time: datetime,
        result: AnalysisResult,
    ) -> None:
        """Check domains against IOC list."""
        domain_clean = domain.lower().rstrip('.')
        if domain_clean in self.iocs[IOCType.DOMAIN]:
            match = IOCMatch(
                ioc_value=domain_clean,
                ioc_type=IOCType.DOMAIN,
                matched_in="dns",
                packet_number=packet_num,
                timestamp=pkt_time,
                severity=Severity.HIGH,
            )
            if not any(m.ioc_value == domain_clean for m in result.ioc_matches):
                result.ioc_matches.append(match)

    def _extract_http_iocs(self, http_trans: HTTPTransaction, result: AnalysisResult) -> None:
        """Extract and check IOCs from HTTP transaction."""
        # Check URL
        if http_trans.full_url.lower() in self.iocs[IOCType.URL]:
            match = IOCMatch(
                ioc_value=http_trans.full_url,
                ioc_type=IOCType.URL,
                matched_in="http",
                timestamp=http_trans.timestamp,
                severity=Severity.HIGH,
                src_ip=http_trans.src_ip,
                dst_ip=http_trans.dst_ip,
            )
            result.ioc_matches.append(match)

        # Check user agent
        if http_trans.user_agent:
            if http_trans.user_agent.lower() in self.iocs[IOCType.USER_AGENT]:
                match = IOCMatch(
                    ioc_value=http_trans.user_agent,
                    ioc_type=IOCType.USER_AGENT,
                    matched_in="http",
                    timestamp=http_trans.timestamp,
                    severity=Severity.MEDIUM,
                )
                result.ioc_matches.append(match)

    def _enrich_with_geo(self, result: AnalysisResult) -> None:
        """Enrich connections with geolocation data."""
        if not self.geo_lookup:
            return

        for conn in result.connections:
            conn.src_geo = self.geo_lookup.lookup(conn.src_ip)
            conn.dst_geo = self.geo_lookup.lookup(conn.dst_ip)

            # Update geo summary
            if conn.dst_geo and conn.dst_geo.country:
                result.geolocation_summary[conn.dst_geo.country] = (
                    result.geolocation_summary.get(conn.dst_geo.country, 0) + 1
                )

    def _detect_suspicious_activities(self, result: AnalysisResult) -> None:
        """Detect various suspicious activities."""

        # Detect port scanning
        src_port_counts: dict[str, set[int]] = defaultdict(set)
        for conn in result.connections:
            src_port_counts[conn.src_ip].add(conn.dst_port)

        for ip, ports in src_port_counts.items():
            if len(ports) > 20:
                result.suspicious_activities.append(SuspiciousActivity(
                    activity_type="port_scan",
                    description=f"Port scanning detected from {ip} ({len(ports)} unique ports)",
                    severity=Severity.MEDIUM,
                    src_ip=ip,
                    evidence=[f"Targeted {len(ports)} unique ports"],
                    mitre_tactics=["Discovery"],
                    mitre_techniques=["T1046 - Network Service Scanning"],
                ))

        # Detect non-standard DNS
        for dns in result.dns_records:
            if dns.dst_ip and dns.dst_ip not in ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]:
                # Check if it's a private IP being used as DNS (normal) or external non-standard
                if not self._is_private_ip(dns.dst_ip):
                    result.suspicious_activities.append(SuspiciousActivity(
                        activity_type="non_standard_dns",
                        description=f"DNS query to non-standard resolver: {dns.dst_ip}",
                        severity=Severity.LOW,
                        dst_ip=dns.dst_ip,
                        evidence=[f"Query: {dns.query_name}"],
                        mitre_tactics=["Command and Control"],
                        mitre_techniques=["T1071.004 - Application Layer Protocol: DNS"],
                    ))
                    break  # Only report once

        # Detect high entropy DNS (possible DGA)
        for dns in result.dns_records:
            entropy = calculate_entropy(dns.query_name.split('.')[0])
            if entropy > 3.5 and len(dns.query_name.split('.')[0]) > 10:
                result.suspicious_activities.append(SuspiciousActivity(
                    activity_type="high_entropy_dns",
                    description=f"High entropy domain detected (possible DGA): {dns.query_name}",
                    severity=Severity.HIGH,
                    evidence=[f"Entropy: {entropy:.2f}"],
                    mitre_tactics=["Command and Control"],
                    mitre_techniques=["T1568.002 - Dynamic Resolution: Domain Generation Algorithms"],
                ))

        # Detect known malicious ports
        suspicious_ports = {
            4444: "Metasploit default",
            5555: "Android Debug Bridge",
            31337: "Back Orifice",
            12345: "NetBus",
            27374: "SubSeven",
            1080: "SOCKS proxy",
            3128: "HTTP proxy",
            8080: "HTTP proxy/alt",
            9001: "Tor",
            9050: "Tor",
        }

        for conn in result.connections:
            if conn.dst_port in suspicious_ports:
                result.suspicious_activities.append(SuspiciousActivity(
                    activity_type="suspicious_port",
                    description=f"Connection to suspicious port {conn.dst_port} ({suspicious_ports[conn.dst_port]})",
                    severity=Severity.MEDIUM,
                    src_ip=conn.src_ip,
                    dst_ip=conn.dst_ip,
                    port=conn.dst_port,
                    protocol=conn.protocol,
                    mitre_tactics=["Command and Control"],
                    mitre_techniques=["T1571 - Non-Standard Port"],
                ))

        # Detect long connections (potential C2)
        for conn in result.connections:
            if conn.duration_seconds > 3600:  # > 1 hour
                result.suspicious_activities.append(SuspiciousActivity(
                    activity_type="long_connection",
                    description=f"Long-lived connection ({conn.duration_seconds/3600:.1f} hours) to {conn.dst_ip}:{conn.dst_port}",
                    severity=Severity.LOW,
                    src_ip=conn.src_ip,
                    dst_ip=conn.dst_ip,
                    port=conn.dst_port,
                    mitre_tactics=["Command and Control"],
                    mitre_techniques=["T1071 - Application Layer Protocol"],
                ))

        # Detect ICMP tunneling (high volume ICMP)
        icmp_bytes = sum(c.bytes_sent for c in result.connections if c.protocol == Protocol.ICMP)
        if icmp_bytes > 100000:  # > 100KB of ICMP
            result.suspicious_activities.append(SuspiciousActivity(
                activity_type="icmp_tunnel",
                description=f"High volume ICMP traffic detected ({icmp_bytes/1024:.1f} KB) - possible tunneling",
                severity=Severity.HIGH,
                evidence=[f"Total ICMP bytes: {icmp_bytes}"],
                mitre_tactics=["Command and Control", "Exfiltration"],
                mitre_techniques=["T1095 - Non-Application Layer Protocol"],
            ))

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private."""
        private_ranges = [
            ("10.", ),
            ("172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
             "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
             "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."),
            ("192.168.",),
            ("127.",),
        ]
        for range_tuple in private_ranges:
            if any(ip.startswith(prefix) for prefix in range_tuple):
                return True
        return False
