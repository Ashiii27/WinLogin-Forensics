"""
WinLogin Forensics - Time utilities
===================================
Timezone normalisation, Windows FILETIME conversion, and duration helpers.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Optional, Union

import pandas as pd
from dateutil import parser as date_parser


WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
FILETIME_EPOCH_DELTA = int((UNIX_EPOCH - WINDOWS_EPOCH).total_seconds() * 10_000_000)


def parse_timestamp(value: Any) -> Optional[pd.Timestamp]:
    """
    Parse a heterogeneous timestamp into a UTC pandas.Timestamp.

    Parameters
    ----------
    value : Any
        ISO-8601 string, datetime, pandas Timestamp, epoch seconds/ms, or None.

    Returns
    -------
    Optional[pd.Timestamp]
        Timezone-aware UTC timestamp, or None if the value is empty/unparseable.
    """
    if value is None or value == "" or value == "-":
        return None
    if isinstance(value, pd.Timestamp):
        ts = value
        if ts.tzinfo is None:
            return ts.tz_localize("UTC")
        return ts.tz_convert("UTC")
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return pd.Timestamp(value).tz_convert("UTC")
    if isinstance(value, (int, float)):
        # Heuristic: values > 1e12 are milliseconds or FILETIME
        num = float(value)
        if num > 1e17:  # Windows FILETIME (100-ns ticks)
            return filetime_to_datetime(int(num))
        if num > 1e12:
            return pd.Timestamp(num, unit="ms", tz="UTC")
        return pd.Timestamp(num, unit="s", tz="UTC")
    try:
        text = str(value).strip()
        if not text:
            return None
        # Windows EVTX often emits 7 fractional digits; dateutil handles this
        dt = date_parser.parse(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return pd.Timestamp(dt).tz_convert("UTC")
    except (ValueError, OverflowError, TypeError, date_parser.ParserError):
        return None


def normalize_to_utc(value: Any) -> Optional[pd.Timestamp]:
    """
    Coerce any supported timestamp representation to UTC.

    Parameters
    ----------
    value : Any
        Timestamp-like input.

    Returns
    -------
    Optional[pd.Timestamp]
        UTC timestamp or None.
    """
    return parse_timestamp(value)


def filetime_to_datetime(filetime: Union[int, str, None]) -> Optional[pd.Timestamp]:
    """
    Convert a Windows FILETIME (100-nanosecond ticks since 1601-01-01 UTC).

    Parameters
    ----------
    filetime : int | str | None
        Raw FILETIME integer (or decimal string).

    Returns
    -------
    Optional[pd.Timestamp]
        UTC timestamp, or None for 0 / invalid values.
    """
    if filetime is None or filetime == "" or filetime == 0:
        return None
    try:
        ticks = int(filetime)
    except (TypeError, ValueError):
        return None
    if ticks <= 0 or ticks > 2650467743999999999:  # ~year 9999
        return None
    try:
        seconds, remainder = divmod(ticks, 10_000_000)
        micros = remainder // 10
        dt = WINDOWS_EPOCH + timedelta(seconds=seconds, microseconds=micros)
        return pd.Timestamp(dt)
    except (OverflowError, OSError, ValueError):
        return None


def time_delta_seconds(start: Any, end: Any) -> float:
    """
    Return the signed duration in seconds between two timestamps.

    Parameters
    ----------
    start, end : Any
        Timestamp-like values.

    Returns
    -------
    float
        ``end - start`` in seconds. Returns 0.0 if either side is missing.
    """
    s = normalize_to_utc(start)
    e = normalize_to_utc(end)
    if s is None or e is None:
        return 0.0
    return float((e - s).total_seconds())


def format_duration(seconds: Optional[float]) -> str:
    """
    Format a duration in seconds as a human-readable string.

    Parameters
    ----------
    seconds : float | None
        Duration in seconds.

    Returns
    -------
    str
        Formatted duration such as ``1h 12m 05s``.
    """
    if seconds is None:
        return "—"
    try:
        total = int(abs(float(seconds)))
    except (TypeError, ValueError):
        return "—"
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def utc_now() -> pd.Timestamp:
    """
    Return the current UTC time as a pandas Timestamp.

    Returns
    -------
    pd.Timestamp
        Current UTC time.
    """
    return pd.Timestamp.now(tz="UTC")


def is_business_hours(ts: Any, start_hour: int = 8, end_hour: int = 18) -> bool:
    """
    Return True if ``ts`` falls inside weekday business hours (local UTC clock).

    Parameters
    ----------
    ts : Any
        Timestamp-like value.
    start_hour, end_hour : int
        Inclusive start hour and exclusive end hour in UTC.

    Returns
    -------
    bool
        True when the timestamp is a weekday within ``[start_hour, end_hour)``.
    """
    stamp = normalize_to_utc(ts)
    if stamp is None:
        return False
    if stamp.dayofweek >= 5:
        return False
    return start_hour <= int(stamp.hour) < end_hour
