"""
STIX 2.1 export for IOCSweep analysis results.

Exports analysis results in STIX 2.1 format for:
- Threat intelligence sharing
- MISP integration
- TAXII server submission
- OpenCTI integration
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from iocsweep.models import AnalysisResult, IOCType, Severity


class STIXExporter:
    """
    Export analysis results to STIX 2.1 format.

    Creates STIX bundles containing:
    - Indicators (IP, domain, URL, hash IOCs)
    - Observed Data (network traffic observations)
    - Malware (detected threats)
    - Attack Patterns (MITRE ATT&CK mappings)
    - Relationships
    """

    STIX_VERSION = "2.1"

    # STIX type mappings
    IOC_TO_STIX_PATTERN = {
        IOCType.IP_ADDRESS: "[ipv4-addr:value = '{}']",
        IOCType.DOMAIN: "[domain-name:value = '{}']",
        IOCType.URL: "[url:value = '{}']",
        IOCType.EMAIL: "[email-addr:value = '{}']",
        IOCType.FILE_HASH_MD5: "[file:hashes.MD5 = '{}']",
        IOCType.FILE_HASH_SHA1: "[file:hashes.'SHA-1' = '{}']",
        IOCType.FILE_HASH_SHA256: "[file:hashes.'SHA-256' = '{}']",
        IOCType.JA3: "[x-ja3-fingerprint:hash = '{}']",
        IOCType.USER_AGENT: "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{}']",
    }

    SEVERITY_TO_CONFIDENCE = {
        Severity.INFO: 20,
        Severity.LOW: 40,
        Severity.MEDIUM: 60,
        Severity.HIGH: 80,
        Severity.CRITICAL: 100,
    }

    def __init__(self, identity_name: str = "IOCSweep", tlp: str = "white"):
        """
        Initialize STIX exporter.

        Args:
            identity_name: Name for the identity object
            tlp: Traffic Light Protocol marking (white, green, amber, red)
        """
        self.identity_name = identity_name
        self.tlp = tlp.lower()
        self.identity_id = self._generate_id("identity")

    def _generate_id(self, stix_type: str, value: str = None) -> str:
        """Generate deterministic STIX ID."""
        if value:
            unique = hashlib.sha256(f"{stix_type}:{value}".encode()).hexdigest()[:8]
        else:
            unique = str(uuid.uuid4())[:8]
        return f"{stix_type}--{unique}-{uuid.uuid4()}"

    def export(self, result: AnalysisResult, output_path: Path | str) -> None:
        """
        Export analysis result to STIX 2.1 bundle.

        Args:
            result: Analysis result to export
            output_path: Path to output file
        """
        bundle = self.create_bundle(result)

        import json
        with open(output_path, 'w') as f:
            json.dump(bundle, f, indent=2, default=str)

    def create_bundle(self, result: AnalysisResult) -> dict:
        """
        Create STIX 2.1 bundle from analysis result.

        Args:
            result: Analysis result

        Returns:
            STIX bundle dictionary
        """
        objects = []

        # Create identity
        identity = self._create_identity()
        objects.append(identity)

        # Create TLP marking
        marking = self._create_tlp_marking()
        objects.append(marking)

        # Create report
        report = self._create_report(result, marking['id'])
        objects.append(report)

        # Create indicators from IOC matches
        indicator_ids = []
        for match in result.ioc_matches:
            indicator = self._create_indicator(match, marking['id'])
            if indicator:
                objects.append(indicator)
                indicator_ids.append(indicator['id'])

        # Create indicators from extracted IOCs
        for ip in result.extracted_ips:
            indicator = self._create_extracted_indicator(
                IOCType.IP_ADDRESS, ip, marking['id']
            )
            if indicator:
                objects.append(indicator)
                indicator_ids.append(indicator['id'])

        for domain in list(result.extracted_domains)[:100]:  # Limit for size
            indicator = self._create_extracted_indicator(
                IOCType.DOMAIN, domain, marking['id']
            )
            if indicator:
                objects.append(indicator)
                indicator_ids.append(indicator['id'])

        for url in list(result.extracted_urls)[:50]:  # Limit for size
            indicator = self._create_extracted_indicator(
                IOCType.URL, url, marking['id']
            )
            if indicator:
                objects.append(indicator)
                indicator_ids.append(indicator['id'])

        for ja3 in result.extracted_ja3_hashes:
            indicator = self._create_extracted_indicator(
                IOCType.JA3, ja3, marking['id']
            )
            if indicator:
                objects.append(indicator)
                indicator_ids.append(indicator['id'])

        # Create attack patterns from MITRE mappings
        attack_pattern_ids = set()
        for activity in result.suspicious_activities:
            for technique in activity.mitre_techniques:
                ap = self._create_attack_pattern(technique, marking['id'])
                if ap and ap['id'] not in attack_pattern_ids:
                    objects.append(ap)
                    attack_pattern_ids.add(ap['id'])

        # Create observed data
        observed = self._create_observed_data(result, marking['id'])
        if observed:
            objects.append(observed)

        # Update report with references
        report['object_refs'] = indicator_ids + list(attack_pattern_ids)
        if observed:
            report['object_refs'].append(observed['id'])

        return {
            'type': 'bundle',
            'id': f"bundle--{uuid.uuid4()}",
            'objects': objects,
        }

    def _create_identity(self) -> dict:
        """Create identity object."""
        return {
            'type': 'identity',
            'spec_version': self.STIX_VERSION,
            'id': self.identity_id,
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'name': self.identity_name,
            'identity_class': 'system',
            'description': 'IOCSweep PCAP Analysis Tool',
        }

    def _create_tlp_marking(self) -> dict:
        """Create TLP marking definition."""
        tlp_map = {
            'white': 'TLP:WHITE',
            'clear': 'TLP:CLEAR',
            'green': 'TLP:GREEN',
            'amber': 'TLP:AMBER',
            'amber+strict': 'TLP:AMBER+STRICT',
            'red': 'TLP:RED',
        }

        return {
            'type': 'marking-definition',
            'spec_version': self.STIX_VERSION,
            'id': f"marking-definition--{uuid.uuid4()}",
            'created': datetime.now(timezone.utc).isoformat(),
            'definition_type': 'tlp',
            'name': tlp_map.get(self.tlp, 'TLP:WHITE'),
            'definition': {
                'tlp': self.tlp,
            },
        }

    def _create_report(self, result: AnalysisResult, marking_id: str) -> dict:
        """Create report object."""
        return {
            'type': 'report',
            'spec_version': self.STIX_VERSION,
            'id': self._generate_id('report'),
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'name': f'IOCSweep Analysis: {Path(result.pcap_file).name}',
            'description': f'Network traffic analysis of {result.pcap_file}. '
                          f'Analyzed {result.total_packets} packets, '
                          f'found {len(result.ioc_matches)} IOC matches, '
                          f'{len(result.suspicious_activities)} suspicious activities.',
            'published': datetime.now(timezone.utc).isoformat(),
            'report_types': ['threat-report', 'attack-pattern'],
            'object_refs': [],
            'object_marking_refs': [marking_id],
            'created_by_ref': self.identity_id,
        }

    def _create_indicator(self, match, marking_id: str) -> dict | None:
        """Create indicator from IOC match."""
        pattern_template = self.IOC_TO_STIX_PATTERN.get(match.ioc_type)
        if not pattern_template:
            return None

        pattern = pattern_template.format(match.ioc_value)

        return {
            'type': 'indicator',
            'spec_version': self.STIX_VERSION,
            'id': self._generate_id('indicator', match.ioc_value),
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'name': f'{match.ioc_type.value}: {match.ioc_value}',
            'description': f'IOC matched in {match.matched_in}',
            'indicator_types': ['malicious-activity'],
            'pattern': pattern,
            'pattern_type': 'stix',
            'valid_from': match.timestamp.isoformat() if match.timestamp else datetime.now(timezone.utc).isoformat(),
            'confidence': self.SEVERITY_TO_CONFIDENCE.get(match.severity, 50),
            'object_marking_refs': [marking_id],
            'created_by_ref': self.identity_id,
        }

    def _create_extracted_indicator(
        self,
        ioc_type: IOCType,
        value: str,
        marking_id: str,
    ) -> dict | None:
        """Create indicator from extracted IOC."""
        pattern_template = self.IOC_TO_STIX_PATTERN.get(ioc_type)
        if not pattern_template:
            return None

        pattern = pattern_template.format(value)

        return {
            'type': 'indicator',
            'spec_version': self.STIX_VERSION,
            'id': self._generate_id('indicator', value),
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'name': f'{ioc_type.value}: {value}',
            'description': f'Extracted from network traffic analysis',
            'indicator_types': ['unknown'],
            'pattern': pattern,
            'pattern_type': 'stix',
            'valid_from': datetime.now(timezone.utc).isoformat(),
            'confidence': 30,  # Lower confidence for extracted (not matched)
            'object_marking_refs': [marking_id],
            'created_by_ref': self.identity_id,
        }

    def _create_attack_pattern(self, technique: str, marking_id: str) -> dict | None:
        """Create attack pattern from MITRE technique."""
        # Parse technique ID (e.g., "T1071 - Application Layer Protocol")
        parts = technique.split(' - ', 1)
        technique_id = parts[0].strip()
        technique_name = parts[1].strip() if len(parts) > 1 else technique_id

        return {
            'type': 'attack-pattern',
            'spec_version': self.STIX_VERSION,
            'id': self._generate_id('attack-pattern', technique_id),
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'name': technique_name,
            'external_references': [
                {
                    'source_name': 'mitre-attack',
                    'external_id': technique_id,
                    'url': f'https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}/',
                }
            ],
            'object_marking_refs': [marking_id],
            'created_by_ref': self.identity_id,
        }

    def _create_observed_data(self, result: AnalysisResult, marking_id: str) -> dict | None:
        """Create observed data object summarizing network observations."""
        if not result.connections:
            return None

        # Create summary of network observations
        objects = {}
        obj_idx = 0

        # Add IP addresses
        for ip in list(result.unique_src_ips | result.unique_dst_ips)[:50]:
            objects[str(obj_idx)] = {
                'type': 'ipv4-addr',
                'value': ip,
            }
            obj_idx += 1

        # Add domains
        for domain in list(result.unique_domains)[:50]:
            objects[str(obj_idx)] = {
                'type': 'domain-name',
                'value': domain,
            }
            obj_idx += 1

        if not objects:
            return None

        return {
            'type': 'observed-data',
            'spec_version': self.STIX_VERSION,
            'id': self._generate_id('observed-data'),
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'first_observed': result.start_time.isoformat(),
            'last_observed': result.end_time.isoformat(),
            'number_observed': result.total_packets,
            'objects': objects,
            'object_marking_refs': [marking_id],
            'created_by_ref': self.identity_id,
        }
