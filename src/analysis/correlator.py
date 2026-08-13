"""
WinLogin Forensics - Cross-source correlator
============================================
Joins Sysmon process / network / DNS activity and PowerShell script
blocks onto reconstructed authentication sessions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pandas as pd

from ..utils.helpers import safe_str
from ..utils.time_utils import normalize_to_utc


class ActivityCorrelator:
    """
    Enrich session rows with host activity that overlaps the session window.

    Purpose
    -------
    * Join Sysmon EID 1 to sessions on ``User`` + overlapping time window
    * Attach network (EID 3) and DNS (EID 22) via the ProcessId chain
    * Attach PowerShell 4103/4104 script blocks on User + time window

    Parameters
    ----------
    sessions : pd.DataFrame
        Output of :class:`SessionCorrelator`.
    sysmon : pd.DataFrame, optional
        Parsed Sysmon events.
    powershell : pd.DataFrame, optional
        Parsed PowerShell operational events.
    slack_seconds : int
        Extra seconds added to each side of the session window.
    """

    def __init__(
        self,
        sessions: pd.DataFrame,
        sysmon: Optional[pd.DataFrame] = None,
        powershell: Optional[pd.DataFrame] = None,
        slack_seconds: int = 60,
    ):
        self.sessions = sessions.copy() if sessions is not None else pd.DataFrame()
        self.sysmon = sysmon.copy() if sysmon is not None and not sysmon.empty else pd.DataFrame()
        self.powershell = (
            powershell.copy() if powershell is not None and not powershell.empty else pd.DataFrame()
        )
        self.slack = pd.Timedelta(seconds=int(slack_seconds))

    def correlate(self) -> pd.DataFrame:
        """
        Return an enriched session DataFrame.

        Returns
        -------
        pd.DataFrame
            Original session columns plus ``linked_processes``,
            ``linked_network``, ``linked_scripts``.
        """
        if self.sessions is None or self.sessions.empty:
            empty = pd.DataFrame()
            empty["linked_processes"] = []
            return empty

        out = self.sessions.copy()
        processes: List[List[Dict[str, Any]]] = []
        networks: List[List[Dict[str, Any]]] = []
        scripts: List[List[Dict[str, Any]]] = []

        for _, sess in out.iterrows():
            procs, nets = self._link_sysmon(sess)
            scrs = self._link_powershell(sess)
            processes.append(procs)
            networks.append(nets)
            scripts.append(scrs)

        out["linked_processes"] = processes
        out["linked_network"] = networks
        out["linked_scripts"] = scripts
        return out

    def _window(self, sess: pd.Series):
        start = normalize_to_utc(sess.get("LogonTime") or sess.get("StartTime"))
        end = normalize_to_utc(sess.get("LogoffTime") or sess.get("EndTime"))
        if start is None:
            return None, None
        start = start - self.slack
        if end is None or pd.isna(end):
            end = start + pd.Timedelta(hours=24)
        else:
            end = end + self.slack
        return start, end

    def _user_match(self, session_user: str, other_user: str) -> bool:
        a = safe_str(session_user).lower()
        b = safe_str(other_user).lower()
        if not a or a == "-" or not b or b == "-":
            return False
        # Sysmon users often look like CORP\Ashish or WORKSTATION\Ashish
        a_short = a.split("\\")[-1]
        b_short = b.split("\\")[-1]
        return a == b or a_short == b_short or a_short in b or b_short in a

    def _link_sysmon(self, sess: pd.Series):
        if self.sysmon.empty:
            return [], []
        start, end = self._window(sess)
        if start is None:
            return [], []
        user = sess.get("Username") or sess.get("TargetUserName")
        time_col = "UtcTime" if "UtcTime" in self.sysmon.columns else "TimeCreated"
        work = self.sysmon.copy()
        work[time_col] = pd.to_datetime(work[time_col], utc=True, errors="coerce")

        # EID 1 processes for this user in window
        eid1 = work[work["EventID"].astype(int) == 1]
        procs = []
        pids = set()
        for _, row in eid1.iterrows():
            ts = row.get(time_col)
            if pd.isna(ts) or ts < start or ts > end:
                continue
            if not self._user_match(user, row.get("User", "-")):
                continue
            pids.add(str(row.get("ProcessId")))
            # walk parent chain ids too so children (often SYSTEM) still attach
            if str(row.get("ParentProcessId")) not in {"-", "", "None"}:
                pids.add(str(row.get("ParentProcessId")))
            procs.append(
                {
                    "ProcessId": str(row.get("ProcessId")),
                    "ParentProcessId": str(row.get("ParentProcessId")),
                    "CommandLine": row.get("CommandLine"),
                    "Image": row.get("Image"),
                    "User": row.get("User"),
                    "Hashes": row.get("Hashes"),
                    "UtcTime": str(ts),
                    "SessionID": sess.get("SessionID"),
                }
            )

        # Expand pids with children that share a parent we already have
        for _, row in eid1.iterrows():
            if str(row.get("ParentProcessId")) in pids:
                pids.add(str(row.get("ProcessId")))

        nets = []
        for eid, kind in ((3, "network"), (22, "dns"), (11, "file")):
            subset = work[work["EventID"].astype(int) == eid]
            for _, row in subset.iterrows():
                ts = row.get(time_col)
                if pd.isna(ts) or ts < start or ts > end:
                    continue
                pid = str(row.get("ProcessId"))
                user_ok = self._user_match(user, row.get("User", "-"))
                if pid not in pids and not user_ok:
                    continue
                nets.append(
                    {
                        "kind": kind,
                        "ProcessId": pid,
                        "DestinationIp": row.get("DestinationIp"),
                        "DestinationPort": row.get("DestinationPort"),
                        "Protocol": row.get("Protocol"),
                        "QueryName": row.get("QueryName"),
                        "QueryResults": row.get("QueryResults"),
                        "TargetFilename": row.get("TargetFilename"),
                        "UtcTime": str(ts),
                        "SessionID": sess.get("SessionID"),
                    }
                )
        return procs, nets

    def _link_powershell(self, sess: pd.Series):
        if self.powershell.empty:
            return []
        start, end = self._window(sess)
        if start is None:
            return []
        user = sess.get("Username") or sess.get("TargetUserName")
        work = self.powershell.copy()
        work["TimeCreated"] = pd.to_datetime(work["TimeCreated"], utc=True, errors="coerce")
        scripts = []
        for _, row in work.iterrows():
            ts = row.get("TimeCreated")
            if pd.isna(ts) or ts < start or ts > end:
                continue
            if not self._user_match(user, row.get("User", "-")):
                continue
            scripts.append(
                {
                    "EventID": int(row.get("EventID", 4104)),
                    "User": row.get("User"),
                    "ScriptBlockText": row.get("ScriptBlockText"),
                    "ModuleName": row.get("ModuleName"),
                    "Suspicious": bool(row.get("Suspicious", False)),
                    "ObfuscationMarkers": row.get("ObfuscationMarkers"),
                    "TimeCreated": str(ts),
                    "SessionID": sess.get("SessionID"),
                }
            )
        return scripts


def enrich_sessions(
    sessions: pd.DataFrame,
    sysmon: Optional[pd.DataFrame] = None,
    powershell: Optional[pd.DataFrame] = None,
    slack_seconds: int = 60,
) -> pd.DataFrame:
    """
    Convenience wrapper around :class:`ActivityCorrelator`.

    Parameters
    ----------
    sessions, sysmon, powershell
        Input frames.
    slack_seconds : int
        Window padding.

    Returns
    -------
    pd.DataFrame
        Enriched sessions.
    """
    return ActivityCorrelator(sessions, sysmon, powershell, slack_seconds=slack_seconds).correlate()
