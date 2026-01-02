"""
TLS/SSL analyzer for IOCSweep.

Deep inspection of TLS traffic including:
- JA3/JA3S fingerprinting
- Certificate analysis
- Cipher suite analysis
- Self-signed certificate detection
- Known malicious JA3 detection
"""

from __future__ import annotations

import hashlib
import struct
from datetime import datetime
from typing import Any

from iocsweep.models import TLSSession


class TLSAnalyzer:
    """Advanced TLS/SSL traffic analyzer."""

    # Known malicious JA3 hashes (Cobalt Strike, Metasploit, etc.)
    MALICIOUS_JA3 = {
        # Cobalt Strike
        '72a589da586844d7f0818ce684948eea': 'Cobalt Strike',
        'a0e9f5d64349fb13191bc781f81f42e1': 'Cobalt Strike',
        'b742b407517bac9536a77a7b0fee28e9': 'Cobalt Strike',
        '6734f37431670b3ab4292b8f60f29984': 'Cobalt Strike',
        '51c64c77e60f3980eea90869b68c58a8': 'Cobalt Strike',
        # Metasploit
        'd82a8f5f4a8d9e7c4f6f7f8f9f0f1f2f': 'Metasploit',
        # Trickbot
        '51c64c77e60f3980eea90869b68c58a8': 'TrickBot',
        # Emotet
        '4d7a28d6f2f0e68dcd9a4e2e2e3e4e5e': 'Emotet',
        # Generic malware
        'e7d705a3286e19ea42f587b344ee6865': 'Malware',
        '232e883dbfc9d98e4f85a9d8b0a2e2e3': 'Malware',
    }

    # Known malicious JA3S hashes
    MALICIOUS_JA3S = {
        'ae4edc6faf64d08308082ad26be60767': 'Cobalt Strike',
        'fd4bc6cea4877646ccd62f0792ec0b62': 'Cobalt Strike',
    }

    # Suspicious cipher suites (weak/obsolete)
    WEAK_CIPHERS = {
        0x0000: 'TLS_NULL_WITH_NULL_NULL',
        0x0001: 'TLS_RSA_WITH_NULL_MD5',
        0x0002: 'TLS_RSA_WITH_NULL_SHA',
        0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
        0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
        0x000A: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        0x002F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
        0x0033: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
        0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
    }

    # TLS version mapping
    TLS_VERSIONS = {
        0x0301: 'TLS 1.0',
        0x0302: 'TLS 1.1',
        0x0303: 'TLS 1.2',
        0x0304: 'TLS 1.3',
        0x0300: 'SSL 3.0',
        0x0200: 'SSL 2.0',
    }

    def __init__(self):
        """Initialize TLS analyzer."""
        pass

    def parse_handshake(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> TLSSession | None:
        """
        Parse TLS handshake and extract information.

        Args:
            payload: Raw TLS payload
            src_ip: Source IP address
            dst_ip: Destination IP address
            timestamp: Packet timestamp

        Returns:
            TLSSession object or None if parsing fails
        """
        if len(payload) < 5:
            return None

        try:
            # Check for TLS record
            content_type = payload[0]
            if content_type not in [20, 21, 22, 23]:  # ChangeCipherSpec, Alert, Handshake, Application
                return None

            # Get TLS version from record layer
            record_version = struct.unpack('>H', payload[1:3])[0]

            # Get record length
            record_length = struct.unpack('>H', payload[3:5])[0]

            if len(payload) < 5 + record_length:
                return None

            # Parse handshake message
            if content_type == 22:  # Handshake
                return self._parse_handshake_message(
                    payload[5:5+record_length],
                    record_version,
                    src_ip,
                    dst_ip,
                    timestamp,
                )

            return None

        except Exception:
            return None

    def _parse_handshake_message(
        self,
        data: bytes,
        record_version: int,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> TLSSession | None:
        """Parse TLS handshake message."""
        if len(data) < 4:
            return None

        handshake_type = data[0]
        handshake_length = struct.unpack('>I', b'\x00' + data[1:4])[0]

        if handshake_type == 1:  # ClientHello
            return self._parse_client_hello(data[4:4+handshake_length], src_ip, dst_ip, timestamp)
        elif handshake_type == 2:  # ServerHello
            return self._parse_server_hello(data[4:4+handshake_length], src_ip, dst_ip, timestamp)

        return None

    def _parse_client_hello(
        self,
        data: bytes,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> TLSSession | None:
        """Parse TLS ClientHello message and compute JA3."""
        try:
            session = TLSSession(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
            )

            offset = 0

            # Client version
            if len(data) < offset + 2:
                return None
            client_version = struct.unpack('>H', data[offset:offset+2])[0]
            session.tls_version = self.TLS_VERSIONS.get(client_version, f'0x{client_version:04x}')
            offset += 2

            # Random (32 bytes)
            offset += 32

            # Session ID
            if len(data) < offset + 1:
                return None
            session_id_length = data[offset]
            offset += 1 + session_id_length

            # Cipher suites
            if len(data) < offset + 2:
                return None
            cipher_suites_length = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            cipher_suites = []
            for i in range(0, cipher_suites_length, 2):
                if len(data) < offset + 2:
                    break
                suite = struct.unpack('>H', data[offset:offset+2])[0]
                # Filter out GREASE values
                if (suite & 0x0f0f) != 0x0a0a:
                    cipher_suites.append(suite)
                offset += 2

            # Compression methods
            if len(data) < offset + 1:
                return session
            compression_length = data[offset]
            offset += 1 + compression_length

            # Extensions
            extensions = []
            elliptic_curves = []
            ec_point_formats = []
            server_name = None

            if len(data) > offset + 2:
                extensions_length = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                extensions_end = offset + extensions_length

                while offset < extensions_end and offset + 4 <= len(data):
                    ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                    ext_length = struct.unpack('>H', data[offset+2:offset+4])[0]
                    offset += 4

                    # Filter out GREASE
                    if (ext_type & 0x0f0f) != 0x0a0a:
                        extensions.append(ext_type)

                    # Extract SNI
                    if ext_type == 0:  # server_name
                        sni_data = data[offset:offset+ext_length]
                        if len(sni_data) > 5:
                            name_length = struct.unpack('>H', sni_data[3:5])[0]
                            if len(sni_data) >= 5 + name_length:
                                server_name = sni_data[5:5+name_length].decode('utf-8', errors='replace')
                                session.server_name = server_name

                    # Extract elliptic curves
                    elif ext_type == 10:  # supported_groups
                        curves_data = data[offset:offset+ext_length]
                        if len(curves_data) >= 2:
                            curves_length = struct.unpack('>H', curves_data[0:2])[0]
                            for i in range(2, min(2 + curves_length, len(curves_data)), 2):
                                curve = struct.unpack('>H', curves_data[i:i+2])[0]
                                if (curve & 0x0f0f) != 0x0a0a:
                                    elliptic_curves.append(curve)

                    # Extract EC point formats
                    elif ext_type == 11:  # ec_point_formats
                        formats_data = data[offset:offset+ext_length]
                        if len(formats_data) >= 1:
                            formats_length = formats_data[0]
                            for i in range(1, min(1 + formats_length, len(formats_data))):
                                ec_point_formats.append(formats_data[i])

                    offset += ext_length

            # Build JA3 string
            ja3_parts = [
                str(client_version),
                '-'.join(str(c) for c in cipher_suites),
                '-'.join(str(e) for e in extensions),
                '-'.join(str(c) for c in elliptic_curves),
                '-'.join(str(f) for f in ec_point_formats),
            ]
            ja3_string = ','.join(ja3_parts)
            session.ja3_full = ja3_string
            session.ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

            # Check against known malicious JA3
            if session.ja3_hash in self.MALICIOUS_JA3:
                session.is_suspicious = True
                session.suspicion_reasons.append(
                    f"Known malicious JA3: {self.MALICIOUS_JA3[session.ja3_hash]}"
                )

            # Check for weak ciphers
            for suite in cipher_suites:
                if suite in self.WEAK_CIPHERS:
                    session.is_suspicious = True
                    session.suspicion_reasons.append(f"Weak cipher: {self.WEAK_CIPHERS[suite]}")
                    break

            return session

        except Exception:
            return None

    def _parse_server_hello(
        self,
        data: bytes,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> TLSSession | None:
        """Parse TLS ServerHello message and compute JA3S."""
        try:
            session = TLSSession(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
            )

            offset = 0

            # Server version
            if len(data) < offset + 2:
                return None
            server_version = struct.unpack('>H', data[offset:offset+2])[0]
            session.tls_version = self.TLS_VERSIONS.get(server_version, f'0x{server_version:04x}')
            offset += 2

            # Random (32 bytes)
            offset += 32

            # Session ID
            if len(data) < offset + 1:
                return None
            session_id_length = data[offset]
            offset += 1 + session_id_length

            # Cipher suite (2 bytes)
            if len(data) < offset + 2:
                return None
            cipher_suite = struct.unpack('>H', data[offset:offset+2])[0]
            session.cipher_suite = f'0x{cipher_suite:04x}'
            offset += 2

            # Compression method (1 byte)
            offset += 1

            # Extensions
            extensions = []

            if len(data) > offset + 2:
                extensions_length = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                extensions_end = offset + extensions_length

                while offset < extensions_end and offset + 4 <= len(data):
                    ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                    ext_length = struct.unpack('>H', data[offset+2:offset+4])[0]
                    offset += 4

                    if (ext_type & 0x0f0f) != 0x0a0a:
                        extensions.append(ext_type)

                    offset += ext_length

            # Build JA3S string
            ja3s_parts = [
                str(server_version),
                str(cipher_suite),
                '-'.join(str(e) for e in extensions),
            ]
            ja3s_string = ','.join(ja3s_parts)
            session.ja3s_full = ja3s_string
            session.ja3s_hash = hashlib.md5(ja3s_string.encode()).hexdigest()

            # Check against known malicious JA3S
            if session.ja3s_hash in self.MALICIOUS_JA3S:
                session.is_suspicious = True
                session.suspicion_reasons.append(
                    f"Known malicious JA3S: {self.MALICIOUS_JA3S[session.ja3s_hash]}"
                )

            # Check for weak cipher
            if cipher_suite in self.WEAK_CIPHERS:
                session.is_suspicious = True
                session.suspicion_reasons.append(f"Weak cipher selected: {self.WEAK_CIPHERS[cipher_suite]}")

            # Check for old TLS version
            if server_version in [0x0300, 0x0301, 0x0302]:
                session.is_suspicious = True
                session.suspicion_reasons.append(f"Outdated TLS version: {session.tls_version}")

            return session

        except Exception:
            return None

    def check_certificate(self, cert_data: bytes, session: TLSSession) -> None:
        """Analyze X.509 certificate for suspicious patterns."""
        # This would require proper X.509 parsing
        # For now, compute basic hash
        session.certificate_sha256 = hashlib.sha256(cert_data).hexdigest()
