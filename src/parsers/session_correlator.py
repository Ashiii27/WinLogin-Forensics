"""
WinLogin Forensics - Session Correlator
=====================================================
Reconstructs Windows user sessions by pairing logon events (EID 4624)
with corresponding logoff events (EID 4634, 4647), RDP reconnect/disconnect (EID 4778, 4779),
and workstation lock/unlock (EID 4800, 4801). Supports batch DataFrame mode
and incremental/streaming real-time monitoring mode.
"""

from typing import List, Dict, Any, Optional
import pandas as pd
from datetime import datetime, timezone

from ..utils.time_utils import normalize_to_utc, time_delta_seconds, format_duration
from ..utils.helpers import get_logon_type_name


class SessionCorrelator:
    """
    Correlates logon and logoff events into discrete user sessions.
    Supports both batch mode (DataFrame) and incremental/streaming mode (real-time).
    """
    def __init__(self, df_events: Optional[pd.DataFrame] = None, timeout_hours: float = 24.0):
        self.df = df_events.copy() if df_events is not None and not df_events.empty else pd.DataFrame()
        self.timeout_seconds = timeout_hours * 3600.0
        self.open_sessions: Dict[str, Dict[str, Any]] = {}

    def correlate(self) -> pd.DataFrame:
        """
        Batch correlate authentication events into session records.
        """
        if self.df.empty or "EventID" not in self.df.columns:
            return pd.DataFrame()

        df_sorted = self.df.sort_values(by="TimeCreated", ascending=True).reset_index(drop=True)
        completed_sessions = []

        for _, row in df_sorted.iterrows():
            eid = int(row.get("EventID", -1))
            user = str(row.get("TargetUserName", "")).strip()
            if not user or user in ("-", "SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE"):
                continue

            logon_type = row.get("LogonType", -1)
            ip_addr = str(row.get("IpAddress", "-"))
            workstation = str(row.get("WorkstationName", "-"))
            ts = normalize_to_utc(row.get("TimeCreated"))
            logon_guid = str(row.get("LogonGuid", "-"))

            # Session key combining user and logon type
            session_key = f"{user.lower()}_{logon_type}"

            if eid in (4624, 4778):  # Logon or RDP Reconnect
                # If there is already an open session for this key, close it as implicit replacement
                if session_key in self.open_sessions:
                    old_sess = self.open_sessions.pop(session_key)
                    dur = time_delta_seconds(old_sess["StartTime"], ts)
                    old_sess["EndTime"] = ts
                    old_sess["DurationSeconds"] = dur
                    old_sess["DurationFormatted"] = format_duration(dur)
                    old_sess["Status"] = "Completed (Implicit Logoff)"
                    completed_sessions.append(old_sess)

                self.open_sessions[session_key] = {
                    "SessionID": f"SESS-{len(completed_sessions) + len(self.open_sessions) + 1001}",
                    "Username": user,
                    "Domain": row.get("TargetDomainName", "-"),
                    "LogonType": logon_type,
                    "LogonTypeName": get_logon_type_name(logon_type),
                    "IpAddress": ip_addr,
                    "WorkstationName": workstation,
                    "LogonGuid": logon_guid,
                    "StartTime": ts,
                    "EndTime": None,
                    "DurationSeconds": 0.0,
                    "DurationFormatted": "Active / Orphaned",
                    "Status": "Orphaned (No Logoff Recorded)",
                    "LockEvents": 0,
                    "UnlockEvents": 0,
                    "StartEventID": eid,
                }

            elif eid in (4634, 4647, 4779):  # Logoff or RDP Disconnect
                if session_key in self.open_sessions:
                    sess = self.open_sessions.pop(session_key)
                    dur = time_delta_seconds(sess["StartTime"], ts)
                    sess["EndTime"] = ts
                    sess["DurationSeconds"] = dur
                    sess["DurationFormatted"] = format_duration(dur)
                    sess["Status"] = "Completed"
                    sess["EndEventID"] = eid
                    completed_sessions.append(sess)

            elif eid == 4800:  # Workstation Locked
                if session_key in self.open_sessions:
                    self.open_sessions[session_key]["LockEvents"] += 1

            elif eid == 4801:  # Workstation Unlocked
                if session_key in self.open_sessions:
                    self.open_sessions[session_key]["UnlockEvents"] += 1

        # Add remaining orphaned sessions
        for sess in self.open_sessions.values():
            completed_sessions.append(sess)

        df_sessions = pd.DataFrame(completed_sessions)
        if not df_sessions.empty:
            df_sessions = df_sessions.sort_values(by="StartTime", ascending=True).reset_index(drop=True)
        return df_sessions

    def process_event(self, event_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Incremental streaming event processing for real-time monitoring mode.
        Returns a completed session dictionary when a logoff closes a session.
        """
        eid = int(event_dict.get("EventID", -1))
        user = str(event_dict.get("TargetUserName", "")).strip()
        if not user or user in ("-", "SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE"):
            return None

        logon_type = event_dict.get("LogonType", -1)
        ip_addr = str(event_dict.get("IpAddress", "-"))
        workstation = str(event_dict.get("WorkstationName", "-"))
        ts = normalize_to_utc(event_dict.get("TimeCreated"))
        logon_guid = str(event_dict.get("LogonGuid", "-"))
        session_key = f"{user.lower()}_{logon_type}"

        if eid in (4624, 4778):
            self.open_sessions[session_key] = {
                "SessionID": f"LIVE-SESS-{int(ts.timestamp())}",
                "Username": user,
                "Domain": event_dict.get("TargetDomainName", "-"),
                "LogonType": logon_type,
                "LogonTypeName": get_logon_type_name(logon_type),
                "IpAddress": ip_addr,
                "WorkstationName": workstation,
                "LogonGuid": logon_guid,
                "StartTime": ts,
                "EndTime": None,
                "DurationSeconds": 0.0,
                "DurationFormatted": "Active / Orphaned",
                "Status": "Active",
                "LockEvents": 0,
                "UnlockEvents": 0,
                "StartEventID": eid,
            }
            return None

        elif eid in (4634, 4647, 4779):
            if session_key in self.open_sessions:
                sess = self.open_sessions.pop(session_key)
                dur = time_delta_seconds(sess["StartTime"], ts)
                sess["EndTime"] = ts
                sess["DurationSeconds"] = dur
                sess["DurationFormatted"] = format_duration(dur)
                sess["Status"] = "Completed"
                sess["EndEventID"] = eid
                return sess

        return None
