"""
Credential extraction from network traffic for IOCSweep.

Extracts credentials from:
- HTTP Basic/Digest/NTLM authentication
- FTP login
- SMTP authentication
- IMAP/POP3 authentication
- Telnet sessions
- Form submissions
"""

from __future__ import annotations

import base64
import re
from datetime import datetime

from iocsweep.models import Credential, Protocol


class CredentialExtractor:
    """
    Extract credentials from network traffic.

    Detects and extracts:
    - HTTP Basic Auth
    - HTTP Digest Auth
    - HTTP NTLM Auth
    - HTTP Form submissions
    - FTP USER/PASS
    - SMTP AUTH
    - IMAP LOGIN
    - POP3 USER/PASS
    - Telnet login sequences
    """

    # Patterns for credential detection
    PATTERNS = {
        'http_basic': re.compile(
            rb'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)',
            re.IGNORECASE
        ),
        'http_digest': re.compile(
            rb'Authorization:\s*Digest\s+(.+?)(?:\r\n|\n)',
            re.IGNORECASE
        ),
        'http_ntlm': re.compile(
            rb'Authorization:\s*(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]+)',
            re.IGNORECASE
        ),
        'http_bearer': re.compile(
            rb'Authorization:\s*Bearer\s+([^\r\n]+)',
            re.IGNORECASE
        ),
        'ftp_user': re.compile(
            rb'USER\s+(\S+)',
            re.IGNORECASE
        ),
        'ftp_pass': re.compile(
            rb'PASS\s+(\S+)',
            re.IGNORECASE
        ),
        'smtp_auth_plain': re.compile(
            rb'AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)',
            re.IGNORECASE
        ),
        'smtp_auth_login': re.compile(
            rb'AUTH\s+LOGIN',
            re.IGNORECASE
        ),
        'imap_login': re.compile(
            rb'LOGIN\s+(\S+)\s+(\S+)',
            re.IGNORECASE
        ),
        'pop3_user': re.compile(
            rb'USER\s+(\S+)',
            re.IGNORECASE
        ),
        'pop3_pass': re.compile(
            rb'PASS\s+(\S+)',
            re.IGNORECASE
        ),
    }

    # Form field patterns
    FORM_USERNAME_FIELDS = [
        'username', 'user', 'login', 'email', 'user_name', 'userid',
        'user_id', 'uname', 'name', 'account', 'usr', 'uid',
    ]

    FORM_PASSWORD_FIELDS = [
        'password', 'pass', 'passwd', 'pwd', 'secret', 'passw',
        'user_password', 'user_pass', 'userpassword', 'passwort',
    ]

    def __init__(self):
        """Initialize credential extractor."""
        self.pending_ftp_user: str | None = None
        self.pending_smtp_login: bool = False
        self.smtp_login_step: int = 0
        self.pending_username: str | None = None

    def extract_from_payload(
        self,
        payload: bytes,
        protocol: Protocol,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> list[Credential]:
        """
        Extract credentials from network payload.

        Args:
            payload: Raw packet payload
            protocol: Detected protocol
            src_ip: Source IP address
            dst_ip: Destination IP address
            timestamp: Packet timestamp

        Returns:
            List of extracted credentials
        """
        credentials = []

        # HTTP credentials
        http_creds = self._extract_http_credentials(payload, src_ip, dst_ip, timestamp)
        credentials.extend(http_creds)

        # FTP credentials
        ftp_creds = self._extract_ftp_credentials(payload, src_ip, dst_ip, timestamp)
        credentials.extend(ftp_creds)

        # SMTP credentials
        smtp_creds = self._extract_smtp_credentials(payload, src_ip, dst_ip, timestamp)
        credentials.extend(smtp_creds)

        # IMAP/POP3 credentials
        mail_creds = self._extract_mail_credentials(payload, src_ip, dst_ip, timestamp)
        credentials.extend(mail_creds)

        # Form submissions
        form_creds = self._extract_form_credentials(payload, src_ip, dst_ip, timestamp)
        credentials.extend(form_creds)

        return credentials

    def _extract_http_credentials(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> list[Credential]:
        """Extract HTTP authentication credentials."""
        credentials = []

        # HTTP Basic Auth
        basic_match = self.PATTERNS['http_basic'].search(payload)
        if basic_match:
            try:
                decoded = base64.b64decode(basic_match.group(1)).decode('utf-8', errors='replace')
                if ':' in decoded:
                    username, password = decoded.split(':', 1)
                    credentials.append(Credential(
                        username=username,
                        password=password,
                        protocol=Protocol.HTTP,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        timestamp=timestamp,
                        is_cleartext=True,
                    ))
            except Exception:
                pass

        # HTTP Digest Auth
        digest_match = self.PATTERNS['http_digest'].search(payload)
        if digest_match:
            digest_data = digest_match.group(1).decode('utf-8', errors='replace')
            username_match = re.search(r'username="([^"]+)"', digest_data)
            if username_match:
                credentials.append(Credential(
                    username=username_match.group(1),
                    hash_type='HTTP-Digest',
                    protocol=Protocol.HTTP,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    timestamp=timestamp,
                    is_cleartext=False,
                ))

        # HTTP NTLM Auth
        ntlm_match = self.PATTERNS['http_ntlm'].search(payload)
        if ntlm_match:
            ntlm_data = ntlm_match.group(1)
            # Parse NTLM Type 3 message for username/domain
            ntlm_info = self._parse_ntlm(ntlm_data)
            if ntlm_info:
                credentials.append(Credential(
                    username=ntlm_info.get('username'),
                    domain=ntlm_info.get('domain'),
                    hash_type='NTLM',
                    protocol=Protocol.HTTP,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    timestamp=timestamp,
                    is_cleartext=False,
                ))

        # Bearer tokens
        bearer_match = self.PATTERNS['http_bearer'].search(payload)
        if bearer_match:
            token = bearer_match.group(1).decode('utf-8', errors='replace')
            credentials.append(Credential(
                password=token,
                hash_type='Bearer-Token',
                protocol=Protocol.HTTP,
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp,
                is_cleartext=True,
            ))

        return credentials

    def _extract_ftp_credentials(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> list[Credential]:
        """Extract FTP credentials."""
        credentials = []

        # FTP USER command
        user_match = self.PATTERNS['ftp_user'].search(payload)
        if user_match:
            self.pending_ftp_user = user_match.group(1).decode('utf-8', errors='replace')

        # FTP PASS command
        pass_match = self.PATTERNS['ftp_pass'].search(payload)
        if pass_match and self.pending_ftp_user:
            password = pass_match.group(1).decode('utf-8', errors='replace')
            credentials.append(Credential(
                username=self.pending_ftp_user,
                password=password,
                protocol=Protocol.FTP,
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp,
                is_cleartext=True,
            ))
            self.pending_ftp_user = None

        return credentials

    def _extract_smtp_credentials(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> list[Credential]:
        """Extract SMTP authentication credentials."""
        credentials = []

        # SMTP AUTH PLAIN
        plain_match = self.PATTERNS['smtp_auth_plain'].search(payload)
        if plain_match:
            try:
                decoded = base64.b64decode(plain_match.group(1)).decode('utf-8', errors='replace')
                parts = decoded.split('\x00')
                if len(parts) >= 3:
                    username = parts[1]
                    password = parts[2]
                    credentials.append(Credential(
                        username=username,
                        password=password,
                        protocol=Protocol.SMTP,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        timestamp=timestamp,
                        is_cleartext=True,
                    ))
            except Exception:
                pass

        # SMTP AUTH LOGIN (multi-step)
        if self.PATTERNS['smtp_auth_login'].search(payload):
            self.pending_smtp_login = True
            self.smtp_login_step = 0
        elif self.pending_smtp_login:
            # Look for base64 encoded username/password
            b64_pattern = re.compile(rb'^([A-Za-z0-9+/=]{4,})$', re.MULTILINE)
            b64_matches = b64_pattern.findall(payload)
            for b64_data in b64_matches:
                try:
                    decoded = base64.b64decode(b64_data).decode('utf-8', errors='replace')
                    if self.smtp_login_step == 0:
                        self.pending_username = decoded
                        self.smtp_login_step = 1
                    elif self.smtp_login_step == 1:
                        credentials.append(Credential(
                            username=self.pending_username,
                            password=decoded,
                            protocol=Protocol.SMTP,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            timestamp=timestamp,
                            is_cleartext=True,
                        ))
                        self.pending_smtp_login = False
                        self.pending_username = None
                except Exception:
                    pass

        return credentials

    def _extract_mail_credentials(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> list[Credential]:
        """Extract IMAP/POP3 credentials."""
        credentials = []

        # IMAP LOGIN
        imap_match = self.PATTERNS['imap_login'].search(payload)
        if imap_match:
            username = imap_match.group(1).decode('utf-8', errors='replace').strip('"')
            password = imap_match.group(2).decode('utf-8', errors='replace').strip('"')
            credentials.append(Credential(
                username=username,
                password=password,
                protocol=Protocol.TCP,  # IMAP
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp,
                is_cleartext=True,
            ))

        # POP3 USER/PASS
        pop3_user = self.PATTERNS['pop3_user'].search(payload)
        if pop3_user:
            self.pending_ftp_user = pop3_user.group(1).decode('utf-8', errors='replace')

        pop3_pass = self.PATTERNS['pop3_pass'].search(payload)
        if pop3_pass and self.pending_ftp_user:
            password = pop3_pass.group(1).decode('utf-8', errors='replace')
            credentials.append(Credential(
                username=self.pending_ftp_user,
                password=password,
                protocol=Protocol.TCP,  # POP3
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp,
                is_cleartext=True,
            ))
            self.pending_ftp_user = None

        return credentials

    def _extract_form_credentials(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> list[Credential]:
        """Extract credentials from HTTP form submissions."""
        credentials = []

        # Check for POST with form data
        if not payload.startswith(b'POST '):
            return credentials

        try:
            payload_str = payload.decode('utf-8', errors='replace')

            # Look for Content-Type: application/x-www-form-urlencoded
            if 'application/x-www-form-urlencoded' not in payload_str:
                return credentials

            # Find the body
            body_start = payload_str.find('\r\n\r\n')
            if body_start < 0:
                return credentials

            body = payload_str[body_start + 4:]

            # Parse form data
            from urllib.parse import parse_qs
            form_data = parse_qs(body)

            username = None
            password = None

            # Look for username fields
            for field in self.FORM_USERNAME_FIELDS:
                if field in form_data:
                    username = form_data[field][0]
                    break

            # Look for password fields
            for field in self.FORM_PASSWORD_FIELDS:
                if field in form_data:
                    password = form_data[field][0]
                    break

            if username or password:
                # Extract URL for context
                url_match = re.search(r'POST\s+(\S+)', payload_str)
                url = url_match.group(1) if url_match else None

                credentials.append(Credential(
                    username=username,
                    password=password,
                    protocol=Protocol.HTTP,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    url=url,
                    timestamp=timestamp,
                    is_cleartext=True,
                ))

        except Exception:
            pass

        return credentials

    def _parse_ntlm(self, ntlm_b64: bytes) -> dict | None:
        """Parse NTLM Type 3 message to extract username and domain."""
        try:
            ntlm_data = base64.b64decode(ntlm_b64)

            # Check NTLM signature
            if not ntlm_data.startswith(b'NTLMSSP\x00'):
                return None

            # Check message type (Type 3 = 0x03)
            msg_type = ntlm_data[8]
            if msg_type != 3:
                return None

            # Parse Type 3 message
            # Domain offset at 28-30
            domain_len = int.from_bytes(ntlm_data[28:30], 'little')
            domain_offset = int.from_bytes(ntlm_data[32:36], 'little')

            # Username offset at 36-38
            user_len = int.from_bytes(ntlm_data[36:38], 'little')
            user_offset = int.from_bytes(ntlm_data[40:44], 'little')

            # Extract domain and username
            domain = ntlm_data[domain_offset:domain_offset + domain_len].decode('utf-16-le', errors='replace')
            username = ntlm_data[user_offset:user_offset + user_len].decode('utf-16-le', errors='replace')

            return {
                'domain': domain,
                'username': username,
            }

        except Exception:
            return None
