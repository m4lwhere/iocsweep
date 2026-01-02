"""
IOCSweep - Advanced PCAP Intelligence Extraction & IOC Hunting Tool

Extract MAXIMUM INTEL VALUE from network packet captures.
"""

__version__ = "2.0.0"
__author__ = "m4lwhere"

from iocsweep.core import IOCSweep
from iocsweep.models import (
    AnalysisResult,
    NetworkConnection,
    DNSRecord,
    HTTPTransaction,
    TLSSession,
    FileExtraction,
    Credential,
    IOCMatch,
)

__all__ = [
    "IOCSweep",
    "AnalysisResult",
    "NetworkConnection",
    "DNSRecord",
    "HTTPTransaction",
    "TLSSession",
    "FileExtraction",
    "Credential",
    "IOCMatch",
]
