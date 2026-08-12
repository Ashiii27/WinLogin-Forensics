"""
WinLogin Forensics - Anti-Forensic Detector
=====================================================
Detects anti-forensic activities including Security/System log clearing (EID 1102, 104),
timestamp manipulation (EID 4616), selective RecordID deletion (sequence gaps),
sudden log volume drops, and SAM vs EVTX creation time discrepancies.
"""

from typing import List, Dict, Any, Optional
import pandas as pd
import numpy as np
from datetime import datetime, timezone

from ..utils.time_utils import normalize_to_utc, time_delta_seconds


class AntiForensicDetector:
    """
    Detector for anti-forensic activities in Windows event logs and Registry artifacts.
    """
    def __init__(self, df_events: pd.DataFrame, sam_records: Optional[List[Dict[str, Any]]] = None):
        self.df = df_events.copy() if not df_events.empty else pd.DataFrame()
        self.sam_records = sam_records or []
        if not self.df.empty and "TimeCreated" in self.df.columns:
            self.df["TimeCreated"] = pd.to_datetime(self.df["TimeCreated"], utc=True)
            self.df = self.df.sort_values("TimeCreated").reset_index(drop=True)

    def detect_log_clearing(self) -> List[Dict[str, Any]]:
        """
        Detect event log clearing (EID 1102 in Security, EID 104 in System).
        """
        findings = []
        if self.df.empty or "EventID" not in self.df.columns:
            return findings

        cleared = self.df[self.df["EventID"].isin([1102, 104])]
        for _, row in cleared.iterrows():
            eid = int(row["EventID"])
            log_type = "Security Audit" if eid == 1102 else "System"
            findings.append({
                "anomaly": "Log Clearing",
                "severity": "High",
                "mitre_id": "T1070.001",
                "timestamp": row["TimeCreated"],
                "details": f"{log_type} event log cleared (Event ID {eid}) by {row.get('SubjectUserName', 'Unknown')}",
                "confidence": 1.0,
                "event_id": eid,
            })
        return findings

    def detect_time_changes(self) -> List[Dict[str, Any]]:
        """
        Detect timestamp manipulation (EID 4616 system time changed).
        """
        findings = []
        if self.df.empty or "EventID" not in self.df.columns:
            return findings

        time_changes = self.df[self.df["EventID"] == 4616]
        for _, row in time_changes.iterrows():
            findings.append({
                "anomaly": "Timestamp Manipulation",
                "severity": "High",
                "mitre_id": "T1070.006",
                "timestamp": row["TimeCreated"],
                "details": f"System time modified (Event ID 4616) by {row.get('SubjectUserName', 'Unknown')}",
                "confidence": 0.95,
                "event_id": 4616,
            })
        return findings

    def detect_record_id_gaps(self, threshold: int = 1) -> List[Dict[str, Any]]:
        """
        Detect selective record deletion via gaps in the EVTX RecordID sequence.
        """
        findings = []
        if self.df.empty or "RecordID" not in self.df.columns or len(self.df) < 2:
            return findings

        # Filter out 0 record IDs and sort by RecordID
        valid_rec = self.df[self.df["RecordID"] > 0].sort_values("RecordID").reset_index(drop=True)
        if len(valid_rec) < 2:
            return findings

        rec_ids = valid_rec["RecordID"].values
        diffs = np.diff(rec_ids)
        gap_indices = np.where(diffs > threshold)[0]

        for idx in gap_indices:
            gap_size = int(diffs[idx] - 1)
            row_before = valid_rec.iloc[idx]
            row_after = valid_rec.iloc[idx + 1]
            findings.append({
                "anomaly": "Selective Record Deletion",
                "severity": "High",
                "mitre_id": "T1070.001",
                "timestamp": row_after["TimeCreated"],
                "details": f"EVTX RecordID sequence gap of {gap_size} missing records between ID #{row_before['RecordID']} and #{row_after['RecordID']}",
                "confidence": 0.90,
                "gap_size": gap_size,
            })
        return findings

    def detect_volume_drops(self, window_hours: int = 1, drop_ratio: float = 0.25) -> List[Dict[str, Any]]:
        """
        Detect sudden drop in event volume compared to the baseline average events per hour.
        """
        findings = []
        if self.df.empty or "TimeCreated" not in self.df.columns or len(self.df) < 10:
            return findings

        df_sorted = self.df.copy()
        df_sorted = df_sorted.set_index("TimeCreated")
        try:
            hourly_counts = df_sorted.resample("1h").size()
        except Exception:
            return findings

        if len(hourly_counts) < 3:
            return findings

        mean_volume = hourly_counts.mean()
        if mean_volume < 5:
            return findings

        for ts, count in hourly_counts.items():
            if count < mean_volume * drop_ratio and mean_volume > 10:
                findings.append({
                    "anomaly": "Log Volume Drop",
                    "severity": "Medium",
                    "mitre_id": "T1070",
                    "timestamp": ts,
                    "details": f"Sudden drop in log volume ({count} events/hour vs baseline mean of {mean_volume:.1f} events/hour)",
                    "confidence": 0.80,
                })
        return findings

    def detect_sam_mismatch(self) -> List[Dict[str, Any]]:
        """
        Detect discrepancies between SAM account creation time and EID 4720 user creation event.
        """
        findings = []
        if self.df.empty or not self.sam_records:
            return findings

        creation_events = self.df[self.df["EventID"] == 4720]
        evtx_creations = {}
        for _, row in creation_events.iterrows():
            uname = str(row.get("TargetUserName", "")).lower().strip()
            if uname and uname != "-":
                evtx_creations[uname] = row["TimeCreated"]

        for sam_user in self.sam_records:
            uname = str(sam_user.get("Username", "")).lower().strip()
            sam_created = sam_user.get("CreationTime")
            if uname in evtx_creations and sam_created:
                ev_created = normalize_to_utc(evtx_creations[uname])
                sm_created = normalize_to_utc(sam_created)
                if time_delta_seconds(ev_created, sm_created) > 300:  # >5 mins mismatch
                    findings.append({
                        "anomaly": "SAM Record Mismatch",
                        "severity": "High",
                        "mitre_id": "T1070",
                        "timestamp": sm_created or ev_created,
                        "details": f"SAM account creation timestamp for '{sam_user.get('Username')}' differs from Event ID 4720 by more than 5 minutes",
                        "confidence": 0.88,
                    })
        return findings

    def run_all(self) -> List[Dict[str, Any]]:
        """
        Run all anti-forensic detectors and return combined findings.
        """
        findings = []
        findings.extend(self.detect_log_clearing())
        findings.extend(self.detect_time_changes())
        findings.extend(self.detect_record_id_gaps())
        findings.extend(self.detect_volume_drops())
        findings.extend(self.detect_sam_mismatch())
        return findings
