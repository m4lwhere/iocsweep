"""
File extraction from network traffic for IOCSweep.

Carves and analyzes files from network streams:
- HTTP file transfers
- Email attachments
- FTP transfers
- Generic file carving
- YARA scanning
- Entropy analysis
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from iocsweep.models import FileExtraction, Protocol
from iocsweep.utils.entropy import calculate_entropy


class FileExtractor:
    """
    Extract and analyze files from network traffic.

    Supports:
    - HTTP file downloads/uploads
    - Email attachments (MIME)
    - Generic file carving by magic bytes
    - Hash calculation (MD5, SHA1, SHA256)
    - YARA rule scanning
    - Entropy analysis for packed/encrypted detection
    """

    # File magic signatures
    FILE_SIGNATURES = {
        # Executables
        b'\x4D\x5A': ('exe', 'application/x-msdownload', True),  # MZ - DOS/Windows executable
        b'\x7F\x45\x4C\x46': ('elf', 'application/x-executable', True),  # ELF - Linux executable
        b'\xCF\xFA\xED\xFE': ('macho', 'application/x-mach-binary', True),  # Mach-O 64-bit
        b'\xCE\xFA\xED\xFE': ('macho', 'application/x-mach-binary', True),  # Mach-O 32-bit

        # Archives
        b'\x50\x4B\x03\x04': ('zip', 'application/zip', False),  # ZIP
        b'\x50\x4B\x05\x06': ('zip', 'application/zip', False),  # ZIP empty
        b'\x50\x4B\x07\x08': ('zip', 'application/zip', False),  # ZIP spanned
        b'\x52\x61\x72\x21': ('rar', 'application/x-rar-compressed', False),  # RAR
        b'\x1F\x8B\x08': ('gz', 'application/gzip', False),  # GZIP
        b'\x42\x5A\x68': ('bz2', 'application/x-bzip2', False),  # BZIP2
        b'\xFD\x37\x7A\x58\x5A\x00': ('xz', 'application/x-xz', False),  # XZ
        b'\x37\x7A\xBC\xAF\x27\x1C': ('7z', 'application/x-7z-compressed', False),  # 7-Zip

        # Documents
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': ('doc', 'application/msword', False),  # OLE (DOC, XLS, PPT)
        b'\x25\x50\x44\x46': ('pdf', 'application/pdf', False),  # PDF
        b'\x7B\x5C\x72\x74\x66': ('rtf', 'application/rtf', False),  # RTF

        # Images
        b'\xFF\xD8\xFF': ('jpg', 'image/jpeg', False),  # JPEG
        b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': ('png', 'image/png', False),  # PNG
        b'\x47\x49\x46\x38': ('gif', 'image/gif', False),  # GIF
        b'\x42\x4D': ('bmp', 'image/bmp', False),  # BMP

        # Scripts
        b'#!/': ('sh', 'application/x-sh', True),  # Shell script
        b'<?php': ('php', 'application/x-php', True),  # PHP
        b'<%': ('asp', 'application/x-asp', True),  # ASP
        b'<script': ('html', 'text/html', True),  # HTML with script

        # Java
        b'\xCA\xFE\xBA\xBE': ('class', 'application/java', True),  # Java class
    }

    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        'exe', 'dll', 'scr', 'pif', 'com', 'bat', 'cmd', 'ps1', 'vbs', 'vbe',
        'js', 'jse', 'wsf', 'wsh', 'msi', 'msp', 'hta', 'cpl', 'jar', 'class',
        'php', 'asp', 'aspx', 'jsp', 'sh', 'bash', 'py', 'pl', 'rb',
    }

    # HTTP Content-Disposition pattern
    CONTENT_DISPOSITION_PATTERN = re.compile(
        r'filename[*]?=["\']?(?:UTF-8\'\')?([^"\';]+)["\']?',
        re.IGNORECASE
    )

    def __init__(self, yara_rules_path: Path | None = None):
        """
        Initialize file extractor.

        Args:
            yara_rules_path: Path to YARA rules file or directory
        """
        self.yara_rules = None
        if yara_rules_path:
            self._load_yara_rules(yara_rules_path)

    def _load_yara_rules(self, path: Path) -> None:
        """Load YARA rules for file scanning."""
        try:
            import yara
            if path.is_file():
                self.yara_rules = yara.compile(filepath=str(path))
            elif path.is_dir():
                rules = {}
                for rule_file in path.glob('*.yar'):
                    rules[rule_file.stem] = str(rule_file)
                for rule_file in path.glob('*.yara'):
                    rules[rule_file.stem] = str(rule_file)
                if rules:
                    self.yara_rules = yara.compile(filepaths=rules)
        except ImportError:
            pass  # YARA not available
        except Exception:
            pass  # Rule compilation error

    def extract_from_stream(self, stream_data: bytes) -> list[FileExtraction]:
        """
        Extract files from a TCP stream.

        Args:
            stream_data: Raw TCP stream data

        Returns:
            List of extracted files
        """
        files = []

        # Try HTTP extraction first
        http_files = self._extract_http_files(stream_data)
        files.extend(http_files)

        # Try MIME extraction (email)
        mime_files = self._extract_mime_files(stream_data)
        files.extend(mime_files)

        # Generic file carving
        carved_files = self._carve_files(stream_data)
        files.extend(carved_files)

        return files

    def _extract_http_files(self, data: bytes) -> list[FileExtraction]:
        """Extract files from HTTP response bodies."""
        files = []

        # Look for HTTP responses
        http_pattern = re.compile(rb'HTTP/[\d.]+\s+200\s+OK\r\n.*?\r\n\r\n', re.DOTALL)

        for match in http_pattern.finditer(data):
            headers_end = match.end()
            headers = data[match.start():headers_end].decode('latin-1', errors='replace')

            # Find content length
            content_length = None
            cl_match = re.search(r'Content-Length:\s*(\d+)', headers, re.IGNORECASE)
            if cl_match:
                content_length = int(cl_match.group(1))

            # Get content type
            content_type = None
            ct_match = re.search(r'Content-Type:\s*([^\r\n;]+)', headers, re.IGNORECASE)
            if ct_match:
                content_type = ct_match.group(1).strip()

            # Get filename
            filename = None
            cd_match = self.CONTENT_DISPOSITION_PATTERN.search(headers)
            if cd_match:
                filename = cd_match.group(1)

            # Extract body
            if content_length:
                body = data[headers_end:headers_end + content_length]
            else:
                # Try to find next HTTP response or end
                next_http = data.find(b'HTTP/', headers_end + 1)
                if next_http > 0:
                    body = data[headers_end:next_http]
                else:
                    body = data[headers_end:]

            if len(body) > 10:  # Minimum file size
                file_info = self._analyze_file(body, filename, content_type)
                if file_info:
                    file_info.source_protocol = Protocol.HTTP
                    files.append(file_info)

        return files

    def _extract_mime_files(self, data: bytes) -> list[FileExtraction]:
        """Extract files from MIME/email content."""
        files = []

        # Look for MIME boundaries
        boundary_pattern = re.compile(rb'boundary="?([^"\r\n]+)"?', re.IGNORECASE)
        boundary_match = boundary_pattern.search(data)

        if boundary_match:
            boundary = boundary_match.group(1)
            parts = data.split(b'--' + boundary)

            for part in parts[1:]:  # Skip first empty part
                if part.startswith(b'--'):
                    continue  # End boundary

                # Split headers from body
                header_end = part.find(b'\r\n\r\n')
                if header_end < 0:
                    continue

                headers = part[:header_end].decode('latin-1', errors='replace')
                body = part[header_end + 4:]

                # Check if this is an attachment
                if 'Content-Disposition' in headers and 'attachment' in headers.lower():
                    filename = None
                    fn_match = self.CONTENT_DISPOSITION_PATTERN.search(headers)
                    if fn_match:
                        filename = fn_match.group(1)

                    content_type = None
                    ct_match = re.search(r'Content-Type:\s*([^\r\n;]+)', headers, re.IGNORECASE)
                    if ct_match:
                        content_type = ct_match.group(1).strip()

                    # Check for base64 encoding
                    if 'base64' in headers.lower():
                        try:
                            import base64
                            body = base64.b64decode(body)
                        except Exception:
                            pass

                    if len(body) > 10:
                        file_info = self._analyze_file(body, filename, content_type)
                        if file_info:
                            file_info.source_protocol = Protocol.SMTP
                            files.append(file_info)

        return files

    def _carve_files(self, data: bytes) -> list[FileExtraction]:
        """Carve files based on magic byte signatures."""
        files = []
        used_offsets = set()

        for signature, (ext, mime, is_exec) in self.FILE_SIGNATURES.items():
            offset = 0
            while True:
                pos = data.find(signature, offset)
                if pos < 0:
                    break

                # Skip if we've already extracted from this offset
                if pos in used_offsets:
                    offset = pos + 1
                    continue

                # Try to determine file end
                file_data = self._extract_file_from_offset(data, pos, ext)
                if file_data and len(file_data) > 100:  # Minimum size
                    file_info = self._analyze_file(file_data, f"carved_{pos}.{ext}", mime)
                    if file_info:
                        file_info.is_executable = is_exec
                        files.append(file_info)
                        used_offsets.add(pos)

                offset = pos + 1

        return files

    def _extract_file_from_offset(self, data: bytes, offset: int, ext: str) -> bytes | None:
        """Extract file data starting from offset."""
        # Maximum file size to extract (10 MB)
        max_size = 10 * 1024 * 1024

        if ext == 'zip':
            # Look for ZIP end signature
            end_sig = b'\x50\x4B\x05\x06'
            end_pos = data.find(end_sig, offset)
            if end_pos > 0:
                return data[offset:end_pos + 22]  # 22 = end central directory size

        elif ext == 'pdf':
            # Look for PDF EOF
            eof_pos = data.find(b'%%EOF', offset)
            if eof_pos > 0:
                return data[offset:eof_pos + 5]

        elif ext in ('jpg', 'jpeg'):
            # Look for JPEG end marker
            end_pos = data.find(b'\xFF\xD9', offset)
            if end_pos > 0:
                return data[offset:end_pos + 2]

        elif ext == 'png':
            # Look for PNG end marker
            end_pos = data.find(b'\x49\x45\x4E\x44\xAE\x42\x60\x82', offset)
            if end_pos > 0:
                return data[offset:end_pos + 8]

        # Default: extract up to max size or next file signature
        return data[offset:offset + max_size]

    def _analyze_file(
        self,
        data: bytes,
        filename: str | None,
        content_type: str | None,
    ) -> FileExtraction | None:
        """Analyze extracted file data."""
        if not data or len(data) < 10:
            return None

        # Calculate hashes
        md5_hash = hashlib.md5(data).hexdigest()
        sha1_hash = hashlib.sha1(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        # Calculate entropy
        entropy = calculate_entropy(data)

        # Detect file type from magic
        magic_type = None
        is_executable = False
        is_archive = False

        for signature, (ext, mime, is_exec) in self.FILE_SIGNATURES.items():
            if data.startswith(signature):
                magic_type = mime
                is_executable = is_exec
                is_archive = ext in ('zip', 'rar', 'gz', 'bz2', 'xz', '7z')
                break

        # Create file extraction object
        file_ext = FileExtraction(
            filename=filename,
            content_type=content_type,
            magic_type=magic_type,
            size=len(data),
            md5=md5_hash,
            sha1=sha1_hash,
            sha256=sha256_hash,
            entropy=entropy,
            data=data,
            is_executable=is_executable,
            is_archive=is_archive,
        )

        # Check for suspicious indicators
        self._check_suspicious(file_ext, data)

        # YARA scanning
        if self.yara_rules:
            self._scan_yara(file_ext, data)

        return file_ext

    def _check_suspicious(self, file_ext: FileExtraction, data: bytes) -> None:
        """Check file for suspicious indicators."""
        # High entropy (packed/encrypted)
        if file_ext.entropy and file_ext.entropy > 7.5:
            file_ext.is_suspicious = True
            file_ext.suspicion_reasons.append(f"High entropy: {file_ext.entropy:.2f} (possible packing/encryption)")

        # Executable with high entropy
        if file_ext.is_executable and file_ext.entropy and file_ext.entropy > 7.0:
            file_ext.is_suspicious = True
            file_ext.suspicion_reasons.append("Executable with high entropy")

        # Check for suspicious strings
        suspicious_strings = [
            b'cmd.exe', b'powershell', b'/bin/sh', b'/bin/bash',
            b'CreateRemoteThread', b'VirtualAlloc', b'WriteProcessMemory',
            b'mimikatz', b'Invoke-Expression', b'IEX(', b'DownloadString',
            b'rundll32', b'regsvr32', b'mshta', b'certutil',
        ]

        for sus_str in suspicious_strings:
            if sus_str in data:
                file_ext.is_suspicious = True
                file_ext.suspicion_reasons.append(f"Contains suspicious string: {sus_str.decode()}")

        # Check filename for suspicious extensions
        if file_ext.filename:
            ext = file_ext.filename.rsplit('.', 1)[-1].lower()
            if ext in self.SUSPICIOUS_EXTENSIONS:
                file_ext.is_suspicious = True
                file_ext.suspicion_reasons.append(f"Suspicious file extension: .{ext}")

            # Double extension trick
            if file_ext.filename.count('.') > 1:
                parts = file_ext.filename.rsplit('.', 2)
                if len(parts) >= 2:
                    second_ext = parts[-2].lower()
                    if second_ext in ('doc', 'pdf', 'jpg', 'png', 'txt'):
                        file_ext.is_suspicious = True
                        file_ext.suspicion_reasons.append("Double extension (possible disguise)")

    def _scan_yara(self, file_ext: FileExtraction, data: bytes) -> None:
        """Scan file with YARA rules."""
        if not self.yara_rules:
            return

        try:
            matches = self.yara_rules.match(data=data)
            for match in matches:
                file_ext.yara_matches.append(str(match))
                file_ext.is_suspicious = True
                file_ext.suspicion_reasons.append(f"YARA match: {match}")
        except Exception:
            pass

    def calculate_ssdeep(self, data: bytes) -> str | None:
        """Calculate ssdeep fuzzy hash."""
        try:
            import ssdeep
            return ssdeep.hash(data)
        except ImportError:
            return None
        except Exception:
            return None
