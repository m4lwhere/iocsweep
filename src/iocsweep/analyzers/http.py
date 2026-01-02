"""
HTTP traffic analyzer for IOCSweep.

Deep inspection of HTTP traffic including:
- Request/response parsing
- Header analysis
- Malicious user-agent detection
- Webshell detection
- C2 pattern detection
- Data exfiltration via HTTP
"""

from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import parse_qs, unquote, urlparse

from iocsweep.models import HTTPTransaction, Severity


class HTTPAnalyzer:
    """Advanced HTTP traffic analyzer."""

    # Known malicious user agents
    MALICIOUS_USER_AGENTS = [
        # Cobalt Strike
        r'Mozilla/5\.0 \(compatible; MSIE 9\.0; Windows NT 6\.1; WOW64; Trident/5\.0\)',
        r'Mozilla/5\.0 \(compatible; MSIE 9\.0; Windows NT 6\.0; Trident/5\.0\)',
        # Metasploit
        r'Mozilla/4\.0 \(compatible; MSIE 6\.0; Windows NT 5\.1\)',
        # Python requests default
        r'python-requests/',
        r'Python-urllib/',
        # curl
        r'^curl/',
        # wget
        r'^Wget/',
        # Common scanners
        r'Nmap Scripting Engine',
        r'nikto',
        r'sqlmap',
        r'masscan',
        r'ZmEu',
        r'Morfeus',
        r'WPScan',
        # Empty or missing
        r'^$',
        r'^-$',
    ]

    # Suspicious URI patterns
    SUSPICIOUS_URI_PATTERNS = [
        # Web shells
        r'/cmd\.php',
        r'/shell\.php',
        r'/c99\.php',
        r'/r57\.php',
        r'/WSO\.php',
        r'/b374k',
        r'/alfa\.php',
        r'/\.well-known/',  # Let's encrypt abuse
        # Common exploit paths
        r'/wp-admin/',
        r'/administrator/',
        r'/phpmyadmin/',
        r'/\.git/',
        r'/\.env',
        r'/\.htaccess',
        r'/config\.php',
        r'/\.svn/',
        r'/backup',
        r'/dump',
        # Common C2 paths
        r'/beacon',
        r'/submit\.php',
        r'/gate\.php',
        r'/panel/',
        r'/admin\.php',
        r'/load\.php',
        r'/upload\.php',
        r'/connect\.php',
        # Directory traversal
        r'\.\./\.\.',
        r'\.\.%2f',
        r'%2e%2e',
        # SQL injection
        r'union\s+select',
        r';\s*drop\s+table',
        r"'\s*or\s+'1'\s*=\s*'1",
        r'--\s*$',
        # Command injection
        r';\s*cat\s+',
        r'\|\s*cat\s+',
        r'`.*`',
        r'\$\(',
        # XXE
        r'<!ENTITY',
        r'<!DOCTYPE.*SYSTEM',
    ]

    # Suspicious response content patterns
    SUSPICIOUS_RESPONSE_PATTERNS = [
        # Credential dumps
        rb'password\s*[:=]',
        rb'username\s*[:=]',
        rb'NTLM\s*hash',
        rb'SAM\s*database',
        # Common backdoor responses
        rb'backdoor',
        rb'webshell',
        rb'cmd\.exe',
        rb'/bin/sh',
        rb'/bin/bash',
        # Ransomware notes
        rb'your files have been encrypted',
        rb'bitcoin',
        rb'ransom',
        # C2 beacons
        rb'beacon_id',
        rb'callback',
        rb'heartbeat',
    ]

    # Suspicious headers
    SUSPICIOUS_HEADERS = [
        'x-powered-by',  # Information disclosure
        'server',  # Information disclosure when verbose
        'x-debug-token',  # Debug enabled
        'x-debug-token-link',
        'x-aspnet-version',
        'x-aspnetmvc-version',
    ]

    def __init__(self):
        """Initialize HTTP analyzer."""
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for performance."""
        self.ua_patterns = [re.compile(p, re.I) for p in self.MALICIOUS_USER_AGENTS]
        self.uri_patterns = [re.compile(p, re.I) for p in self.SUSPICIOUS_URI_PATTERNS]
        self.response_patterns = [re.compile(p, re.I) for p in self.SUSPICIOUS_RESPONSE_PATTERNS]

    def parse_transaction(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> HTTPTransaction | None:
        """
        Parse HTTP request/response from payload.

        Args:
            payload: Raw HTTP payload
            src_ip: Source IP address
            dst_ip: Destination IP address
            timestamp: Packet timestamp

        Returns:
            HTTPTransaction object or None if parsing fails
        """
        try:
            # Try to decode payload
            try:
                payload_str = payload.decode('utf-8', errors='replace')
            except Exception:
                payload_str = payload.decode('latin-1', errors='replace')

            lines = payload_str.split('\r\n')
            if not lines:
                return None

            first_line = lines[0]

            # Check if request or response
            if first_line.startswith('HTTP/'):
                return self._parse_response(payload, payload_str, lines, src_ip, dst_ip, timestamp)
            elif any(first_line.startswith(m) for m in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ']):
                return self._parse_request(payload, payload_str, lines, src_ip, dst_ip, timestamp)

            return None

        except Exception:
            return None

    def _parse_request(
        self,
        payload: bytes,
        payload_str: str,
        lines: list[str],
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> HTTPTransaction | None:
        """Parse HTTP request."""
        try:
            first_line = lines[0]
            parts = first_line.split(' ')
            if len(parts) < 2:
                return None

            method = parts[0]
            uri = parts[1]

            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            # Extract body
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''

            # Create transaction
            trans = HTTPTransaction(
                method=method,
                host=headers.get('host', dst_ip),
                uri=uri,
                user_agent=headers.get('user-agent'),
                referer=headers.get('referer'),
                content_type=headers.get('content-type'),
                request_headers=headers,
                request_body=body.encode() if body else None,
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
            )

            # Parse cookies
            if 'cookie' in headers:
                trans.cookies = self._parse_cookies(headers['cookie'])

            # Analyze for suspicious patterns
            self._analyze_request(trans)

            return trans

        except Exception:
            return None

    def _parse_response(
        self,
        payload: bytes,
        payload_str: str,
        lines: list[str],
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> HTTPTransaction | None:
        """Parse HTTP response."""
        try:
            first_line = lines[0]
            parts = first_line.split(' ')
            if len(parts) < 2:
                return None

            status_code = int(parts[1])

            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            # Extract body
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''

            # Create transaction (partial - response only)
            trans = HTTPTransaction(
                method='RESPONSE',
                host=headers.get('server', ''),
                uri='',
                content_type=headers.get('content-type'),
                status_code=status_code,
                response_headers=headers,
                response_body=body.encode() if body else None,
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
            )

            # Analyze response
            self._analyze_response(trans, payload)

            return trans

        except Exception:
            return None

    def _parse_cookies(self, cookie_header: str) -> dict[str, str]:
        """Parse cookie header into dictionary."""
        cookies = {}
        for cookie in cookie_header.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
        return cookies

    def _analyze_request(self, trans: HTTPTransaction) -> None:
        """Analyze HTTP request for suspicious patterns."""
        # Check user agent
        if trans.user_agent:
            for pattern in self.ua_patterns:
                if pattern.search(trans.user_agent):
                    trans.is_suspicious = True
                    trans.suspicion_reasons.append(f"Suspicious user-agent: {trans.user_agent[:50]}")
                    break

        # Check URI patterns
        for pattern in self.uri_patterns:
            if pattern.search(trans.uri):
                trans.is_suspicious = True
                trans.suspicion_reasons.append(f"Suspicious URI pattern: {pattern.pattern}")

        # Check for credentials in URI
        if self._contains_credentials(trans.uri):
            trans.contains_credentials = True
            trans.is_suspicious = True
            trans.suspicion_reasons.append("Credentials in URI")

        # Check for data in URI (possible exfil)
        parsed = urlparse(trans.uri)
        if parsed.query:
            params = parse_qs(parsed.query)
            for key, values in params.items():
                for value in values:
                    if len(value) > 100:  # Long parameter values
                        trans.is_suspicious = True
                        trans.suspicion_reasons.append(f"Long parameter value in {key}")

        # Check for POST with credentials
        if trans.method == 'POST' and trans.request_body:
            body_str = trans.request_body.decode('utf-8', errors='replace').lower()
            if any(cred in body_str for cred in ['password', 'passwd', 'pwd', 'pass']):
                trans.contains_credentials = True

        # Check for encoded content in URI
        decoded_uri = unquote(trans.uri)
        if decoded_uri != trans.uri:
            # Check decoded content for malicious patterns
            for pattern in self.uri_patterns:
                if pattern.search(decoded_uri):
                    trans.is_suspicious = True
                    trans.suspicion_reasons.append(f"Encoded malicious pattern: {pattern.pattern}")

    def _analyze_response(self, trans: HTTPTransaction, raw_payload: bytes) -> None:
        """Analyze HTTP response for suspicious patterns."""
        # Check for suspicious response patterns
        for pattern in self.response_patterns:
            if pattern.search(raw_payload):
                trans.is_suspicious = True
                trans.suspicion_reasons.append(f"Suspicious response content: {pattern.pattern.decode()[:30]}")

        # Check for suspicious headers
        for header in self.SUSPICIOUS_HEADERS:
            if header in trans.response_headers:
                trans.suspicion_reasons.append(f"Information disclosure: {header}")

        # Check for error pages with stack traces
        if trans.response_body:
            body_str = trans.response_body.decode('utf-8', errors='replace').lower()
            if 'stack trace' in body_str or 'exception' in body_str:
                trans.suspicion_reasons.append("Error page with stack trace")

    def _contains_credentials(self, uri: str) -> bool:
        """Check if URI contains credentials."""
        # Check for basic auth in URL
        if '@' in uri and '://' in uri:
            return True

        # Check for common credential parameters
        cred_params = ['password', 'passwd', 'pwd', 'pass', 'secret', 'token', 'api_key', 'apikey']
        parsed = urlparse(uri)
        if parsed.query:
            params = parse_qs(parsed.query)
            return any(param.lower() in cred_params for param in params.keys())

        return False

    def extract_urls(self, trans: HTTPTransaction) -> list[str]:
        """Extract URLs from HTTP transaction."""
        urls = [trans.full_url]

        # Extract from referer
        if trans.referer:
            urls.append(trans.referer)

        # Extract from response body (links)
        if trans.response_body:
            body_str = trans.response_body.decode('utf-8', errors='replace')
            url_pattern = re.compile(r'https?://[^\s<>"\']+')
            urls.extend(url_pattern.findall(body_str))

        return list(set(urls))

    def extract_emails(self, trans: HTTPTransaction) -> list[str]:
        """Extract email addresses from HTTP transaction."""
        emails = []
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

        # Check request
        if trans.request_body:
            body_str = trans.request_body.decode('utf-8', errors='replace')
            emails.extend(email_pattern.findall(body_str))

        # Check response
        if trans.response_body:
            body_str = trans.response_body.decode('utf-8', errors='replace')
            emails.extend(email_pattern.findall(body_str))

        return list(set(emails))
