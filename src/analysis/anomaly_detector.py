"""
WinLogin Forensics - Rule-based anomaly detector
================================================
Flags brute force, pass-the-hash, Kerberoasting, orphaned privileged
sessions, after-hours logons, account/persistence events, and more.
Each finding is tagged with a MITRE ATT&CK technique ID.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional

import pandas as pd

from ..report.mitre_mapper import lookup_technique_id
from ..utils.helpers import is_system_account, safe_str
from ..utils.time_utils import is_business_hours, normalize_to_utc


RC4_MARKERS = {"0x17", "17", "0x0017", "rc4", "rc4_hmac", "0X17"}


class AnomalyDetector:
    """
    Rule-based detector over a parsed event DataFrame and optional sessions.

    Parameters
    ----------
    events : pd.DataFrame
        Parsed EVTX events.
    sessions : pd.DataFrame, optional
        Output of :class:`SessionCorrelator`.
    brute_force_threshold : int
        Failed logons within the window that constitute brute force.
    brute_force_window_minutes : int
        Sliding window for 4625 aggregation.
    """

    def __init__(
        self,
        events: Optional[pd.DataFrame] = None,
        sessions: Optional[pd.DataFrame] = None,
        brute_force_threshold: int = 5,
        brute_force_window_minutes: int = 5,
    ):
        self.events = events if events is not None else pd.DataFrame()
        self.sessions = sessions if sessions is not None else pd.DataFrame()
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window_minutes = brute_force_window_minutes

    def detect(self) -> List[Dict[str, Any]]:
        """
        Run every rule and return a list of finding dicts.

        Returns
        -------
        List[dict]
            Findings with ``anomaly``, ``mitre_id``, ``severity``,
            ``timestamp``, ``details``, ``confidence``.
        """
        findings: List[Dict[str, Any]] = []
        if self.events is None or self.events.empty:
            findings.extend(self._orphaned_privileged())
            return findings
        findings.extend(self.detect_brute_force())
        findings.extend(self.detect_pass_the_hash())
        findings.extend(self.detect_kerberoasting())
        findings.extend(self.detect_asrep())
        findings.extend(self.detect_privilege())
        findings.extend(self.detect_account_ops())
        findings.extend(self.detect_persistence())
        findings.extend(self.detect_after_hours())
        findings.extend(self._orphaned_privileged())
        return findings

    def detect_brute_force(self) -> List[Dict[str, Any]]:
        """Flag ≥N failed logons (4625) from the same IP within the window."""
        df = self._eid(4625)
        if df.empty:
            return []
        findings = []
        df = df.sort_values("TimeCreated")
        # Group by source IP (fallback: workstation)
        key_col = "IpAddress" if "IpAddress" in df.columns else "WorkstationName"
        window = pd.Timedelta(minutes=self.brute_force_window_minutes)
        for key, group in df.groupby(key_col):
            if safe_str(key) in {"-", "", "None"}:
                # still group by target user if IP missing
                pass
            times = list(group["TimeCreated"])
            users = list(group.get("TargetUserName", pd.Series(["-"] * len(group))))
            i = 0
            for j in range(len(times)):
                while times[j] - times[i] > window:
                    i += 1
                count = j - i + 1
                if count >= self.brute_force_threshold and (j == len(times) - 1 or times[j + 1] - times[i] > window):
                    uniq = {str(u) for u in users[i : j + 1]}
                    findings.append(
                        self._finding(
                            "Brute Force Attack",
                            "T1110.001",
                            "High",
                            times[j],
                            f"{count} failed logons (4625) from {key} within "
                            f"{self.brute_force_window_minutes} minutes "
                            f"against {len(uniq)} account(s): {', '.join(sorted(uniq)[:8])}",
                            0.95,
                            event_id=4625,
                            rule="Repeated 4625",
                        )
                    )
        # Dedup: keep one finding per key
        seen = set()
        uniq_f = []
        for f in findings:
            sig = (f["details"][:40], str(f["timestamp"]))
            if sig in seen:
                continue
            seen.add(sig)
            uniq_f.append(f)
        return uniq_f

    def detect_pass_the_hash(self) -> List[Dict[str, Any]]:
        """Flag explicit-credential use (4648) and Type-3 NTLM patterns."""
        findings = []
        df = self._eid(4648)
        for _, row in df.iterrows():
            findings.append(
                self._finding(
                    "Pass-the-Hash / Explicit Credential",
                    "T1550.002",
                    "High",
                    row.get("TimeCreated"),
                    f"Explicit credentials used by {row.get('SubjectUserName', '-')} "
                    f"as {row.get('TargetUserName', '-')} from {row.get('IpAddress', '-')} "
                    f"(Event 4648)",
                    0.85,
                    event_id=4648,
                    rule="Pass-the-Hash pattern",
                )
            )
        return findings

    def detect_kerberoasting(self) -> List[Dict[str, Any]]:
        """Flag 4769 service tickets requested with RC4 (0x17)."""
        df = self._eid(4769)
        findings = []
        if df.empty:
            return findings
        enc_col = "TicketEncryptionType" if "TicketEncryptionType" in df.columns else None
        for _, row in df.iterrows():
            enc = str(row.get(enc_col, "") if enc_col else "").strip().lower()
            raw = row.get("RawData") if "RawData" in df.columns else {}
            if not enc and isinstance(raw, dict):
                enc = str(raw.get("TicketEncryptionType", "")).strip().lower()
            if enc in RC4_MARKERS or enc.replace("0x", "") == "17":
                findings.append(
                    self._finding(
                        "Kerberoasting",
                        "T1558.003",
                        "High",
                        row.get("TimeCreated"),
                        f"Kerberos service ticket (4769) for "
                        f"{row.get('ServiceName', row.get('TargetUserName', '-'))} "
                        f"requested with RC4 (TicketEncryptionType={enc})",
                        0.92,
                        event_id=4769,
                        rule="Kerberoasting (4769)",
                    )
                )
        return findings

    def detect_asrep(self) -> List[Dict[str, Any]]:
        """Flag Kerberos pre-auth failures (4771) as AS-REP roasting candidates."""
        df = self._eid(4771)
        return [
            self._finding(
                "AS-REP Roasting",
                "T1558.004",
                "Medium",
                row.get("TimeCreated"),
                f"Kerberos pre-authentication failed (4771) for {row.get('TargetUserName', '-')}",
                0.7,
                event_id=4771,
            )
            for _, row in df.iterrows()
        ]

    def detect_privilege(self) -> List[Dict[str, Any]]:
        """Flag special privilege assignment (4672) on non-machine accounts."""
        df = self._eid(4672)
        findings = []
        for _, row in df.iterrows():
            user = safe_str(row.get("TargetUserName") or row.get("SubjectUserName"))
            if is_system_account(user):
                continue
            findings.append(
                self._finding(
                    "Admin Privilege Escalation",
                    "T1078.002",
                    "High",
                    row.get("TimeCreated"),
                    f"Special privileges assigned (4672) to {user} "
                    f"logon {row.get('TargetLogonId', '-')}",
                    0.8,
                    event_id=4672,
                )
            )
        return findings

    def detect_account_ops(self) -> List[Dict[str, Any]]:
        """Flag account create / group add / lockout events."""
        findings = []
        mapping = {
            4720: ("New Account Created", "T1136.001", "High"),
            4726: ("Account Deleted", "T1098", "High"),
            4732: ("Group Membership Change", "T1098.007", "Medium"),
            4728: ("Group Membership Change", "T1098.007", "Medium"),
            4756: ("Group Membership Change", "T1098.007", "Medium"),
            4740: ("Account Lockout", "T1110", "Medium"),
        }
        if self.events.empty:
            return findings
        for eid, (name, mitre, sev) in mapping.items():
            for _, row in self._eid(eid).iterrows():
                findings.append(
                    self._finding(
                        name,
                        mitre,
                        sev,
                        row.get("TimeCreated"),
                        f"Event {eid} — target {row.get('TargetUserName', '-')} "
                        f"by {row.get('SubjectUserName', '-')}",
                        0.9,
                        event_id=eid,
                    )
                )
        return findings

    def detect_persistence(self) -> List[Dict[str, Any]]:
        """Flag scheduled tasks (4698) and new services (7045)."""
        findings = []
        for _, row in self._eid(4698).iterrows():
            findings.append(
                self._finding(
                    "Scheduled Task Created",
                    "T1053.005",
                    "Medium",
                    row.get("TimeCreated"),
                    f"Scheduled task created: {row.get('TaskName', '-')}",
                    0.88,
                    event_id=4698,
                )
            )
        for _, row in self._eid(7045).iterrows():
            findings.append(
                self._finding(
                    "New Service Installed",
                    "T1543.003",
                    "Medium",
                    row.get("TimeCreated"),
                    f"New service installed: {row.get('ServiceName', '-')}",
                    0.88,
                    event_id=7045,
                )
            )
        return findings

    def detect_after_hours(self) -> List[Dict[str, Any]]:
        """Flag successful logons outside 08:00–18:00 UTC weekdays."""
        findings = []
        for _, row in self._eid(4624).iterrows():
            ts = row.get("TimeCreated")
            user = safe_str(row.get("TargetUserName"))
            if is_system_account(user):
                continue
            if not is_business_hours(ts):
                findings.append(
                    self._finding(
                        "After-Hours Login",
                        "T1078",
                        "Medium",
                        ts,
                        f"Successful logon for {user} outside business hours "
                        f"(type {row.get('LogonType', '-')})",
                        0.6,
                        event_id=4624,
                    )
                )
        return findings

    def _orphaned_privileged(self) -> List[Dict[str, Any]]:
        """Flag sessions that are orphaned AND privileged (4672 / admin)."""
        if self.sessions is None or self.sessions.empty:
            return []
        findings = []
        for _, row in self.sessions.iterrows():
            status = str(row.get("Status", "")).lower()
            priv = bool(row.get("HasSpecialPrivileges", False))
            user = safe_str(row.get("Username"))
            if status == "orphaned" and (priv or user.lower() in {"administrator", "admin"}):
                findings.append(
                    self._finding(
                        "Orphaned privileged session",
                        "T1078",
                        "High",
                        row.get("LogonTime"),
                        f"Privileged session for {user} (LogonId "
                        f"{row.get('TargetLogonId', '-')}) has no matching logoff",
                        0.84,
                        event_id=4624,
                        rule="Orphaned privileged session",
                    )
                )
        return findings

    def _eid(self, event_id: int) -> pd.DataFrame:
        if self.events is None or self.events.empty or "EventID" not in self.events.columns:
            return pd.DataFrame()
        return self.events[self.events["EventID"].astype(int) == int(event_id)].copy()

    @staticmethod
    def _finding(
        name: str,
        mitre_id: str,
        severity: str,
        timestamp,
        details: str,
        confidence: float,
        event_id: int = -1,
        rule: str = "",
    ) -> Dict[str, Any]:
        if not mitre_id:
            mitre_id = lookup_technique_id(rule or name) or "T0000"
        return {
            "anomaly": name,
            "detection_type": name,
            "mitre_id": mitre_id,
            "severity": severity,
            "timestamp": normalize_to_utc(timestamp),
            "details": details,
            "evidence_detail": details,
            "confidence": confidence,
            "event_id": event_id,
            "rule": rule or name,
        }


def detect_anomalies(
    events: pd.DataFrame,
    sessions: Optional[pd.DataFrame] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """
    Convenience wrapper around :class:`AnomalyDetector`.

    Parameters
    ----------
    events : pd.DataFrame
        Parsed events.
    sessions : pd.DataFrame, optional
        Correlated sessions.
    **kwargs
        Forwarded to :class:`AnomalyDetector`.

    Returns
    -------
    List[dict]
        Findings.
    """
    return AnomalyDetector(events, sessions, **kwargs).detect()
