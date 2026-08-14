"""
WinLogin Forensics - Parsers Package
"""
from .evtx_parser import EvtxParser, SUPPORTED_EVENT_IDS, EVENT_SCHEMA, parse_evtx
from .antiforensic_detector import AntiForensicDetector
from .registry_parser import RegistryParser, REMOTE_ACCESS_TOOLS
from .session_correlator import SessionCorrelator, correlate_sessions
from .sysmon_parser import SysmonParser, SYSMON_EVENT_IDS
from .powershell_parser import PowerShellParser, SUSPICIOUS_KEYWORDS, OBFUSCATION_MARKERS

__all__ = [
    "EvtxParser",
    "SUPPORTED_EVENT_IDS",
    "EVENT_SCHEMA",
    "parse_evtx",
    "AntiForensicDetector",
    "RegistryParser",
    "REMOTE_ACCESS_TOOLS",
    "SessionCorrelator",
    "correlate_sessions",
    "SysmonParser",
    "SYSMON_EVENT_IDS",
    "PowerShellParser",
    "SUSPICIOUS_KEYWORDS",
]
