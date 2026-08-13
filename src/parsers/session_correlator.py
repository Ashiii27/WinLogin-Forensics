"""
WinLogin Forensics - Session Correlator
=======================================
Reconstructs Windows user sessions by pairing successful logons (EID 4624)
with logoffs (EID 4634 / 4647) on ``TargetLogonId``. Supports batch DataFrame
mode and incremental streaming for live monitoring.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

import pandas as pd

from ..utils.helpers import get_logon_type_name, is_system_account, safe_int, safe_str
from ..utils.time_utils import format_duration, normalize_to_utc, time_delta_seconds


SESSION_COLUMNS: List[str] = [
    "SessionID",
    "TargetLogonId",
    "Username",
    "Domain",
    "LogonType",
    "LogonTypeName",
    "IpAddress",
    "WorkstationName",
    "LogonTime",
    "LogoffTime",
    "DurationSeconds",
    "DurationFormatted",
    "Status",
    "OverlapFlag",
    "OverlapSessionIDs",
    "HasSpecialPrivileges",
    "StartEventID",
    "EndEventID",
    "SubjectUserName",
]

LOGON_EVENT_IDS = {4624}
LOGOFF_EVENT_IDS = {4634, 4647}
# RDP reconnect/disconnect treated as secondary logon/logoff signals
RDP_LOGON_IDS = {4778}
RDP_LOGOFF_IDS = {4779}


class SessionCorrelator:
    """
    Correlate logon and logoff events into discrete user sessions.

    Purpose
    -------
    Join 4624 records to 4634/4647 records on ``TargetLogonId``, compute
    non-negative session duration, tag each session as ``active``,
    ``closed`` or ``orphaned``, and flag overlapping sessions for the
    same user on the same workstation.

    Parameters
    ----------
    df_events : pd.DataFrame, optional
        Pre-loaded event table (used by ``correlate()`` when no argument
        is passed).
    timeout_hours : float
        Age after which an unmatched live session is expired (streaming).
    """

    def __init__(
        self,
        df_events: Optional[pd.DataFrame] = None,
        timeout_hours: float = 24.0,
    ):
        self.df = df_events.copy() if df_events is not None and not df_events.empty else pd.DataFrame()
        self.timeout_seconds = float(timeout_hours) * 3600.0
        self.open_sessions: Dict[str, Dict[str, Any]] = {}
        self._seq = 0

    def correlate(self, events: Optional[pd.DataFrame] = None) -> pd.DataFrame:
        """
        Batch-correlate authentication events into session records.

        Parameters
        ----------
        events : pd.DataFrame, optional
            Event table. Falls back to the DataFrame supplied at init.

        Returns
        -------
        pd.DataFrame
            One row per reconstructed session. Durations are always >= 0.
        """
        df = events if events is not None else self.df
        if df is None or df.empty or "EventID" not in df.columns:
            return self._empty()

        work = df.copy()
        work["TimeCreated"] = pd.to_datetime(work["TimeCreated"], utc=True, errors="coerce")
        work = work.sort_values("TimeCreated", ascending=True).reset_index(drop=True)

        # Privilege map: TargetLogonId → True when 4672 observed
        privileged: set = set()
        if "TargetLogonId" in work.columns:
            priv_rows = work[work["EventID"].astype(int) == 4672]
            for lid in priv_rows["TargetLogonId"].astype(str):
                if lid and lid != "-":
                    privileged.add(lid.lower())

        open_by_id: Dict[str, Dict[str, Any]] = {}
        completed: List[Dict[str, Any]] = []

        for _, row in work.iterrows():
            eid = int(row.get("EventID", -1))
            logon_id = _norm_logon_id(row.get("TargetLogonId"))
            user = safe_str(row.get("TargetUserName"), default="")
            ts = normalize_to_utc(row.get("TimeCreated"))

            if eid in LOGON_EVENT_IDS or eid in RDP_LOGON_IDS:
                if is_system_account(user):
                    continue
                if not logon_id:
                    # Synthesize a key so the event is not silently dropped
                    logon_id = f"synth-{user.lower()}-{ts}"
                if logon_id in open_by_id:
                    # Duplicate 4624 for same id — close previous as implicit
                    old = open_by_id.pop(logon_id)
                    completed.append(self._close(old, ts, status="closed", end_eid=eid, implicit=True))
                open_by_id[logon_id] = self._new_session(row, ts, logon_id, privileged)
            elif eid in LOGOFF_EVENT_IDS or eid in RDP_LOGOFF_IDS:
                if not logon_id:
                    continue
                if logon_id in open_by_id:
                    sess = open_by_id.pop(logon_id)
                    completed.append(self._close(sess, ts, status="closed", end_eid=eid))
            elif eid == 4800 and logon_id in open_by_id:
                open_by_id[logon_id]["LockEvents"] = open_by_id[logon_id].get("LockEvents", 0) + 1
            elif eid == 4801 and logon_id in open_by_id:
                open_by_id[logon_id]["UnlockEvents"] = open_by_id[logon_id].get("UnlockEvents", 0) + 1

        # Remaining opens: orphaned in batch mode (no matching logoff)
        for sess in open_by_id.values():
            sess["Status"] = "orphaned"
            sess["DurationFormatted"] = "Orphaned (no logoff)"
            completed.append(sess)

        result = pd.DataFrame(completed)
        if result.empty:
            return self._empty()
        result = self._tag_overlaps(result)
        result = result.sort_values("LogonTime", ascending=True).reset_index(drop=True)
        return result

    def process_event(self, event_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Incrementally ingest one event (live / streaming mode).

        Parameters
        ----------
        event_dict : dict
            A single parsed event.

        Returns
        -------
        Optional[dict]
            A completed session dict when a logoff closes a session,
            otherwise None. Open sessions are held in ``open_sessions``.
        """
        eid = int(event_dict.get("EventID", -1))
        user = safe_str(event_dict.get("TargetUserName"), default="")
        if is_system_account(user) and eid in LOGON_EVENT_IDS | RDP_LOGON_IDS:
            return None
        logon_id = _norm_logon_id(event_dict.get("TargetLogonId"))
        ts = normalize_to_utc(event_dict.get("TimeCreated"))

        if eid in LOGON_EVENT_IDS | RDP_LOGON_IDS:
            if not logon_id:
                logon_id = f"live-{user.lower()}-{ts}"
            sess = self._new_session(event_dict, ts, logon_id, set())
            sess["Status"] = "active"
            sess["DurationFormatted"] = "Active"
            self.open_sessions[logon_id] = sess
            return None

        if eid in LOGOFF_EVENT_IDS | RDP_LOGOFF_IDS and logon_id in self.open_sessions:
            sess = self.open_sessions.pop(logon_id)
            return self._close(sess, ts, status="closed", end_eid=eid)
        return None

    def expire_stale(self, now: Any = None) -> List[Dict[str, Any]]:
        """
        Expire live sessions older than ``timeout_hours``.

        Parameters
        ----------
        now : Any
            Reference timestamp (defaults to current UTC).

        Returns
        -------
        List[dict]
            Sessions flipped from ``active`` to ``orphaned``.
        """
        from ..utils.time_utils import utc_now

        ref = normalize_to_utc(now) or utc_now()
        expired: List[Dict[str, Any]] = []
        for key in list(self.open_sessions.keys()):
            sess = self.open_sessions[key]
            age = time_delta_seconds(sess.get("LogonTime"), ref)
            if age > self.timeout_seconds:
                sess["Status"] = "orphaned"
                sess["DurationFormatted"] = "Expired (no logoff)"
                expired.append(self.open_sessions.pop(key))
        return expired

    def snapshot(self) -> pd.DataFrame:
        """
        Return currently open (active) live sessions as a DataFrame.

        Returns
        -------
        pd.DataFrame
            Active sessions.
        """
        if not self.open_sessions:
            return self._empty()
        return pd.DataFrame(list(self.open_sessions.values()))

    # ------------------------------------------------------------------

    def _new_session(self, row: Any, ts, logon_id: str, privileged: set) -> Dict[str, Any]:
        self._seq += 1
        get = row.get if hasattr(row, "get") else lambda k, d=None: row[k] if k in row else d
        user = safe_str(get("TargetUserName"))
        domain = safe_str(get("TargetDomainName") or get("Domain"))
        logon_type = safe_int(get("LogonType"), default=-1)
        lid_key = logon_id.lower()
        return {
            "SessionID": f"SESS-{self._seq:04d}",
            "TargetLogonId": logon_id,
            "Username": user,
            "Domain": domain,
            "LogonType": logon_type,
            "LogonTypeName": get_logon_type_name(logon_type),
            "IpAddress": safe_str(get("IpAddress")),
            "WorkstationName": safe_str(get("WorkstationName") or get("Computer")),
            "LogonTime": ts,
            "LogoffTime": pd.NaT,
            "DurationSeconds": 0.0,
            "DurationFormatted": "Orphaned (no logoff)",
            "Status": "orphaned",
            "OverlapFlag": False,
            "OverlapSessionIDs": "",
            "HasSpecialPrivileges": lid_key in privileged,
            "StartEventID": safe_int(get("EventID"), default=4624),
            "EndEventID": -1,
            "SubjectUserName": safe_str(get("SubjectUserName")),
            "LockEvents": 0,
            "UnlockEvents": 0,
        }

    @staticmethod
    def _close(
        sess: Dict[str, Any],
        ts,
        status: str = "closed",
        end_eid: int = 4634,
        implicit: bool = False,
    ) -> Dict[str, Any]:
        start = sess.get("LogonTime")
        dur = time_delta_seconds(start, ts)
        if dur < 0:
            dur = 0.0
        sess["LogoffTime"] = ts
        sess["DurationSeconds"] = float(dur)
        sess["DurationFormatted"] = format_duration(dur)
        sess["Status"] = "closed"
        sess["EndEventID"] = end_eid
        if implicit:
            sess["Status"] = "closed"
        return sess

    @staticmethod
    def _tag_overlaps(df: pd.DataFrame) -> pd.DataFrame:
        """Flag sessions for the same user+workstation with overlapping windows."""
        if df.empty:
            return df
        df = df.copy()
        df["OverlapFlag"] = False
        df["OverlapSessionIDs"] = ""
        n = len(df)
        for i in range(n):
            a = df.iloc[i]
            overlaps: List[str] = []
            a_end = a["LogoffTime"] if pd.notna(a["LogoffTime"]) else a["LogonTime"] + pd.Timedelta(days=1)
            for j in range(n):
                if i == j:
                    continue
                b = df.iloc[j]
                if str(a["Username"]).lower() != str(b["Username"]).lower():
                    continue
                if str(a["WorkstationName"]).lower() != str(b["WorkstationName"]).lower():
                    continue
                if str(a["WorkstationName"]) in {"-", ""}:
                    continue
                b_end = b["LogoffTime"] if pd.notna(b["LogoffTime"]) else b["LogonTime"] + pd.Timedelta(days=1)
                if a["LogonTime"] < b_end and b["LogonTime"] < a_end:
                    overlaps.append(str(b["SessionID"]))
            if overlaps:
                df.at[df.index[i], "OverlapFlag"] = True
                df.at[df.index[i], "OverlapSessionIDs"] = ",".join(overlaps)
        return df

    @staticmethod
    def _empty() -> pd.DataFrame:
        return pd.DataFrame(columns=SESSION_COLUMNS)


def _norm_logon_id(value: Any) -> str:
    text = safe_str(value, default="").strip()
    if not text or text == "-":
        return ""
    return text


def correlate_sessions(events: pd.DataFrame, timeout_hours: float = 24.0) -> pd.DataFrame:
    """
    Convenience function wrapping :class:`SessionCorrelator`.

    Parameters
    ----------
    events : pd.DataFrame
        Parsed event table.
    timeout_hours : float
        Live-session timeout (unused in batch mode).

    Returns
    -------
    pd.DataFrame
        Session table.
    """
    return SessionCorrelator(events, timeout_hours=timeout_hours).correlate()
