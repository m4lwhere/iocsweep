"""
Entropy calculation utilities for IOCSweep.

Entropy is used to detect:
- Encrypted/packed files
- DGA domains
- Encoded data exfiltration
- Random/obfuscated strings
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Union


def calculate_entropy(data: Union[str, bytes]) -> float:
    """
    Calculate Shannon entropy of data.

    Entropy measures randomness/unpredictability:
    - 0.0 = completely uniform (e.g., "aaaaaaa")
    - ~4.5 = typical English text
    - ~5.5 = compressed/encoded data
    - ~7.5+ = encrypted/random data
    - 8.0 = maximum (completely random bytes)

    Args:
        data: String or bytes to calculate entropy for

    Returns:
        Entropy value between 0 and 8 (for bytes) or log2(charset) for strings
    """
    if not data:
        return 0.0

    # Convert string to bytes if needed
    if isinstance(data, str):
        # For strings, we calculate on character frequency
        return _string_entropy(data)
    else:
        return _byte_entropy(data)


def _byte_entropy(data: bytes) -> float:
    """Calculate entropy for bytes (0-8 scale)."""
    if not data:
        return 0.0

    # Count byte frequencies
    byte_counts = Counter(data)
    length = len(data)

    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


def _string_entropy(data: str) -> float:
    """Calculate entropy for string (scaled for character set)."""
    if not data:
        return 0.0

    # Count character frequencies
    char_counts = Counter(data.lower())
    length = len(data)

    # Calculate entropy
    entropy = 0.0
    for count in char_counts.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


def is_high_entropy(data: Union[str, bytes], threshold: float = 7.0) -> bool:
    """
    Check if data has high entropy (likely encrypted/random).

    Args:
        data: Data to check
        threshold: Entropy threshold (default 7.0 for bytes)

    Returns:
        True if entropy exceeds threshold
    """
    return calculate_entropy(data) > threshold


def entropy_analysis(data: bytes) -> dict:
    """
    Perform detailed entropy analysis on binary data.

    Args:
        data: Binary data to analyze

    Returns:
        Dictionary with entropy statistics
    """
    if not data:
        return {
            'entropy': 0.0,
            'is_encrypted': False,
            'is_compressed': False,
            'is_text': False,
            'byte_distribution': {},
        }

    entropy = _byte_entropy(data)

    # Analyze byte distribution
    byte_counts = Counter(data)
    unique_bytes = len(byte_counts)

    # Check for null bytes and printable characters
    null_count = byte_counts.get(0, 0)
    printable_count = sum(1 for b in data if 32 <= b <= 126)

    # Determine likely type
    is_text = printable_count / len(data) > 0.8
    is_encrypted = entropy > 7.5 and unique_bytes > 200
    is_compressed = 7.0 < entropy <= 7.5 and unique_bytes > 200

    return {
        'entropy': round(entropy, 4),
        'unique_bytes': unique_bytes,
        'null_byte_ratio': round(null_count / len(data), 4),
        'printable_ratio': round(printable_count / len(data), 4),
        'is_encrypted': is_encrypted,
        'is_compressed': is_compressed,
        'is_text': is_text,
        'classification': _classify_entropy(entropy, is_text),
    }


def _classify_entropy(entropy: float, is_text: bool) -> str:
    """Classify data based on entropy value."""
    if entropy < 1.0:
        return 'uniform/sparse'
    elif entropy < 3.0:
        return 'low_complexity'
    elif entropy < 5.0:
        if is_text:
            return 'natural_text'
        return 'structured'
    elif entropy < 6.5:
        return 'encoded/base64'
    elif entropy < 7.5:
        return 'compressed'
    else:
        return 'encrypted/random'


def chunk_entropy(data: bytes, chunk_size: int = 256) -> list[tuple[int, float]]:
    """
    Calculate entropy for chunks of data.

    Useful for detecting encrypted sections within files.

    Args:
        data: Binary data to analyze
        chunk_size: Size of each chunk

    Returns:
        List of (offset, entropy) tuples
    """
    results = []

    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        if len(chunk) >= chunk_size // 2:  # Skip very small final chunks
            entropy = _byte_entropy(chunk)
            results.append((i, entropy))

    return results


def detect_encrypted_sections(data: bytes, threshold: float = 7.5, min_size: int = 1024) -> list[tuple[int, int]]:
    """
    Detect potentially encrypted sections in binary data.

    Args:
        data: Binary data to analyze
        threshold: Entropy threshold for encrypted detection
        min_size: Minimum size of section to report

    Returns:
        List of (start_offset, end_offset) tuples for encrypted sections
    """
    chunk_entropies = chunk_entropy(data, 256)
    sections = []
    section_start = None

    for offset, ent in chunk_entropies:
        if ent >= threshold:
            if section_start is None:
                section_start = offset
        else:
            if section_start is not None:
                if offset - section_start >= min_size:
                    sections.append((section_start, offset))
                section_start = None

    # Handle final section
    if section_start is not None:
        if len(data) - section_start >= min_size:
            sections.append((section_start, len(data)))

    return sections
