"""WinLogin Forensics - Utilities package."""

from .helpers import (
    LOGON_TYPE_NAMES,
    get_logon_type_name,
    haversine_km,
    is_system_account,
    rot13_decode,
    safe_int,
    safe_str,
    sha256_bytes,
    sha256_file,
)
from .safe_reader import (
    EvidenceTamperedError,
    EvidenceWriteAttemptError,
    ReadOnlyEvidenceFile,
    compute_file_hash,
    open_evidence,
)
from .time_utils import (
    filetime_to_datetime,
    format_duration,
    normalize_to_utc,
    parse_timestamp,
    time_delta_seconds,
    utc_now,
)

__all__ = [
    "LOGON_TYPE_NAMES",
    "get_logon_type_name",
    "haversine_km",
    "is_system_account",
    "rot13_decode",
    "safe_int",
    "safe_str",
    "sha256_bytes",
    "sha256_file",
    "EvidenceTamperedError",
    "EvidenceWriteAttemptError",
    "ReadOnlyEvidenceFile",
    "compute_file_hash",
    "open_evidence",
    "filetime_to_datetime",
    "format_duration",
    "normalize_to_utc",
    "parse_timestamp",
    "time_delta_seconds",
    "utc_now",
]
