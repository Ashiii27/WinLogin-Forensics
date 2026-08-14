"""
WinLogin Forensics - Shared helpers
===================================
Logon-type names, ROT13 (UserAssist), hashing, and safe coercions.
"""

from __future__ import annotations

import codecs
import hashlib
import math
from pathlib import Path
from typing import Any, Iterable, Optional, Union


LOGON_TYPE_NAMES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
    12: "CachedRemoteInteractive",
    13: "CachedUnlock",
}

SYSTEM_ACCOUNTS = {
    "-",
    "",
    "system",
    "anonymous logon",
    "local service",
    "network service",
    "dwm-1",
    "dwm-2",
    "umfd-0",
    "umfd-1",
}


def get_logon_type_name(logon_type: Any) -> str:
    """
    Map a numeric Windows logon type to its display name.

    Parameters
    ----------
    logon_type : Any
        Integer logon type (or coercible string).

    Returns
    -------
    str
        Human-readable logon type name.
    """
    try:
        code = int(logon_type)
    except (TypeError, ValueError):
        return "Unknown"
    return LOGON_TYPE_NAMES.get(code, f"Type {code}")


def rot13_decode(value: Any) -> str:
    """
    Decode a ROT13-encoded UserAssist path or GUID string.

    Parameters
    ----------
    value : Any
        Encoded string. Non-string inputs are coerced.

    Returns
    -------
    str
        ROT13-decoded string. Returns empty string for empty input.
    """
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    return codecs.decode(text, "rot_13")


def sha256_file(path: Union[str, Path]) -> str:
    """
    Compute the SHA-256 hex digest of a file.

    Parameters
    ----------
    path : str | Path
        File path.

    Returns
    -------
    str
        Lowercase hex digest.
    """
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: Union[str, bytes]) -> str:
    """
    Compute the SHA-256 hex digest of in-memory content.

    Parameters
    ----------
    data : str | bytes
        Content to hash. Strings are encoded as UTF-8.

    Returns
    -------
    str
        Lowercase hex digest.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def is_system_account(name: Any) -> bool:
    """
    Return True if ``name`` is a built-in / non-user Windows account.

    Parameters
    ----------
    name : Any
        Account name.

    Returns
    -------
    bool
        True for SYSTEM, ANONYMOUS LOGON, services, and empty names.
    """
    if name is None:
        return True
    text = str(name).strip().lower()
    if text in SYSTEM_ACCOUNTS:
        return True
    if text.endswith("$"):  # machine accounts
        return True
    return False


def safe_int(value: Any, default: int = -1) -> int:
    """
    Coerce ``value`` to int, returning ``default`` on failure.

    Parameters
    ----------
    value : Any
        Input value.
    default : int
        Fallback.

    Returns
    -------
    int
        Parsed integer or default.
    """
    if value is None or value == "" or value == "-":
        return default
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_str(value: Any, default: str = "-") -> str:
    """
    Coerce ``value`` to a cleaned string.

    Parameters
    ----------
    value : Any
        Input value.
    default : str
        Fallback for empty/None.

    Returns
    -------
    str
        Cleaned string.
    """
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Great-circle distance in kilometres between two WGS84 coordinates.

    Parameters
    ----------
    lat1, lon1, lat2, lon2 : float
        Coordinates in decimal degrees.

    Returns
    -------
    float
        Distance in kilometres.
    """
    radius = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * radius * math.asin(min(1.0, math.sqrt(a)))


def flatten_unique(values: Iterable[Any]) -> list:
    """
    Flatten one level of iterables and drop duplicates while preserving order.

    Parameters
    ----------
    values : Iterable
        Input values.

    Returns
    -------
    list
        Unique values.
    """
    seen = set()
    out = []
    for item in values:
        key = item if not isinstance(item, list) else tuple(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
