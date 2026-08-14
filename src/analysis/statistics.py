"""
WinLogin Forensics - Summary statistics
=======================================
Aggregation helpers consumed by the UI, CLI, and HTML report.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pandas as pd


def event_summary(events: pd.DataFrame) -> Dict[str, Any]:
    """
    Compute high-level event statistics.

    Parameters
    ----------
    events : pd.DataFrame
        Parsed events.

    Returns
    -------
    dict
        Totals and breakdowns.
    """
    if events is None or events.empty:
        return {"total": 0, "by_event_id": {}, "by_user": {}, "failed": 0, "success": 0}
    by_eid = events["EventID"].value_counts().to_dict() if "EventID" in events.columns else {}
    by_user = {}
    if "TargetUserName" in events.columns:
        by_user = (
            events[events["TargetUserName"].astype(str) != "-"]["TargetUserName"]
            .value_counts()
            .head(20)
            .to_dict()
        )
    return {
        "total": int(len(events)),
        "by_event_id": {int(k): int(v) for k, v in by_eid.items()},
        "by_user": {str(k): int(v) for k, v in by_user.items()},
        "failed": int((events["EventID"] == 4625).sum()) if "EventID" in events.columns else 0,
        "success": int((events["EventID"] == 4624).sum()) if "EventID" in events.columns else 0,
    }


def session_summary(sessions: pd.DataFrame) -> Dict[str, Any]:
    """
    Compute session-status totals.

    Parameters
    ----------
    sessions : pd.DataFrame
        Correlated sessions.

    Returns
    -------
    dict
        Counts by status plus average duration.
    """
    if sessions is None or sessions.empty:
        return {"total": 0, "closed": 0, "orphaned": 0, "active": 0, "avg_duration_seconds": 0.0}
    status = sessions["Status"].astype(str).str.lower() if "Status" in sessions.columns else pd.Series(dtype=str)
    return {
        "total": int(len(sessions)),
        "closed": int(status.str.contains("closed").sum()) if len(status) else 0,
        "orphaned": int(status.str.contains("orphan").sum()) if len(status) else 0,
        "active": int(status.str.contains("active").sum()) if len(status) else 0,
        "avg_duration_seconds": float(sessions["DurationSeconds"].mean())
        if "DurationSeconds" in sessions.columns
        else 0.0,
    }


def severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Count findings by severity label.

    Parameters
    ----------
    findings : list of dict
        Detector output.

    Returns
    -------
    dict
        ``{High, Medium, Low, total}``.
    """
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for item in findings or []:
        sev = str(item.get("severity", "Low")).capitalize()
        if sev not in counts:
            sev = "Low"
        counts[sev] += 1
    counts["total"] = sum(counts.values())
    return counts
