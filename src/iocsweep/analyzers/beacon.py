"""
Beacon pattern analyzer for IOCSweep.

Detects Command & Control beaconing patterns including:
- Regular interval detection
- Jitter analysis
- Sleep pattern detection
- Known C2 framework patterns
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import datetime

from iocsweep.models import BeaconPattern


class BeaconAnalyzer:
    """
    Detect C2 beaconing patterns in network traffic.

    Beaconing is when malware periodically "phones home" to a C2 server.
    This analyzer looks for:
    - Regular communication intervals
    - Low jitter (variance in timing)
    - Consistent destination
    """

    # Common beacon intervals (in seconds) used by known malware
    KNOWN_INTERVALS = {
        60: 'Common 1-minute beacon',
        300: 'Common 5-minute beacon',
        600: 'Common 10-minute beacon',
        900: 'Common 15-minute beacon',
        1800: 'Common 30-minute beacon',
        3600: 'Common 1-hour beacon',
    }

    def __init__(
        self,
        min_connections: int = 10,
        max_jitter_percent: float = 20.0,
        min_confidence: float = 0.7,
    ):
        """
        Initialize beacon analyzer.

        Args:
            min_connections: Minimum connections to analyze for beaconing
            max_jitter_percent: Maximum jitter percentage to flag as beacon
            min_confidence: Minimum confidence score to flag
        """
        self.min_connections = min_connections
        self.max_jitter_percent = max_jitter_percent
        self.min_confidence = min_confidence

    def detect_beacons(
        self,
        connection_times: dict[str, list[datetime]],
    ) -> list[BeaconPattern]:
        """
        Detect beaconing patterns from connection timestamps.

        Args:
            connection_times: Dictionary mapping destination:port to list of timestamps

        Returns:
            List of detected beacon patterns
        """
        patterns = []

        for dest, times in connection_times.items():
            if len(times) < self.min_connections:
                continue

            # Sort times
            sorted_times = sorted(times)

            # Calculate intervals
            intervals = []
            for i in range(1, len(sorted_times)):
                interval = (sorted_times[i] - sorted_times[i-1]).total_seconds()
                if interval > 0:  # Ignore same-second connections
                    intervals.append(interval)

            if len(intervals) < self.min_connections - 1:
                continue

            # Calculate statistics
            try:
                mean_interval = statistics.mean(intervals)
                if mean_interval < 5:  # Skip very fast connections (likely not beacons)
                    continue

                stddev = statistics.stdev(intervals) if len(intervals) > 1 else 0
                jitter_percent = (stddev / mean_interval * 100) if mean_interval > 0 else 100

                # Parse destination
                parts = dest.rsplit(':', 1)
                dst_ip = parts[0]
                dst_port = int(parts[1]) if len(parts) > 1 else 0

                # Calculate confidence score
                confidence = self._calculate_confidence(
                    len(times),
                    jitter_percent,
                    mean_interval,
                )

                # Determine if this is likely a beacon
                is_beacon = (
                    jitter_percent <= self.max_jitter_percent and
                    confidence >= self.min_confidence
                )

                pattern = BeaconPattern(
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    interval_mean=mean_interval,
                    interval_stddev=stddev,
                    jitter_percent=jitter_percent,
                    connection_count=len(times),
                    first_seen=sorted_times[0],
                    last_seen=sorted_times[-1],
                    is_likely_beacon=is_beacon,
                    confidence=confidence,
                )

                patterns.append(pattern)

            except Exception:
                continue

        # Sort by confidence (most likely beacons first)
        patterns.sort(key=lambda p: p.confidence, reverse=True)

        return patterns

    def _calculate_confidence(
        self,
        connection_count: int,
        jitter_percent: float,
        mean_interval: float,
    ) -> float:
        """
        Calculate beacon confidence score.

        Args:
            connection_count: Number of connections
            jitter_percent: Jitter percentage
            mean_interval: Mean interval between connections

        Returns:
            Confidence score between 0 and 1
        """
        # Base confidence from jitter (lower jitter = higher confidence)
        if jitter_percent <= 5:
            jitter_score = 1.0
        elif jitter_percent <= 10:
            jitter_score = 0.9
        elif jitter_percent <= 20:
            jitter_score = 0.7
        elif jitter_percent <= 30:
            jitter_score = 0.5
        else:
            jitter_score = 0.3

        # Bonus for connection count
        if connection_count >= 50:
            count_score = 1.0
        elif connection_count >= 20:
            count_score = 0.8
        elif connection_count >= 10:
            count_score = 0.6
        else:
            count_score = 0.4

        # Bonus for known beacon intervals
        interval_score = 0.5
        for known_interval in self.KNOWN_INTERVALS:
            # Check if mean interval is within 20% of known interval
            if abs(mean_interval - known_interval) / known_interval < 0.2:
                interval_score = 1.0
                break

        # Weighted average
        confidence = (
            jitter_score * 0.5 +
            count_score * 0.3 +
            interval_score * 0.2
        )

        return round(confidence, 2)

    def get_beacon_summary(self, patterns: list[BeaconPattern]) -> dict:
        """
        Generate summary of beacon patterns.

        Args:
            patterns: List of beacon patterns

        Returns:
            Dictionary with beacon summary statistics
        """
        if not patterns:
            return {
                'total_patterns': 0,
                'likely_beacons': 0,
                'suspicious_destinations': [],
            }

        likely_beacons = [p for p in patterns if p.is_likely_beacon]

        return {
            'total_patterns': len(patterns),
            'likely_beacons': len(likely_beacons),
            'suspicious_destinations': [
                {
                    'ip': p.dst_ip,
                    'port': p.dst_port,
                    'interval': f'{p.interval_mean:.1f}s',
                    'jitter': f'{p.jitter_percent:.1f}%',
                    'confidence': f'{p.confidence:.0%}',
                    'connections': p.connection_count,
                }
                for p in likely_beacons[:10]
            ],
        }

    def format_interval(self, seconds: float) -> str:
        """Format interval in human-readable form."""
        if seconds < 60:
            return f'{seconds:.1f}s'
        elif seconds < 3600:
            return f'{seconds/60:.1f}m'
        elif seconds < 86400:
            return f'{seconds/3600:.1f}h'
        else:
            return f'{seconds/86400:.1f}d'
