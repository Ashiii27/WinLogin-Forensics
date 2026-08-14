"""
WinLogin Forensics - Anti-Forensic Detector
===========================================
Detects tampering inside the log stream itself: Security/System log
clearing (EID 1102, 104), timestamp manipulation (EID 4616), selective
RecordID deletion (sequence gaps), and sudden 1-hour volume drops.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from ..utils.time_utils import normalize_to_utc, time_delta_seconds


OUTPUT_SCHEMA = [
    "detection_type",
    "event_id",
    "timestamp",
    "evidence_detail",
    "severity",
]


class AntiForensicDetector:
    """
    Detector for anti-forensic activity in Windows event logs.

    Purpose
    -------
    Inspect a parsed event DataFrame (and optional SAM records) and emit
    findings that match the contract schema
    ``detection_type, event_id, timestamp, evidence_detail, severity``.

    Parameters
    ----------
    df_events : pd.DataFrame
        Parsed events. Should include EventID, TimeCreated, RecordID.
    sam_records : list of dict, optional
        SAM account rows for creation-time mismatch checks.
    volume_drop_ratio : float
        Flag when the current hour's count is less than
        ``(1 - volume_drop_ratio)`` of the prior hour (default 0.80 = 80%).
    """

    def __init__(
        self,
        df_events: Optional[pd.DataFrame] = None,
        sam_records: Optional[List[Dict[str, Any]]] = None,
        volume_drop_ratio: float = 0.80,
    ):
        self.df = df_events.copy() if df_events is not None and not df_events.empty else pd.DataFrame()
        self.sam_records = sam_records or []
        self.volume_drop_ratio = float(volume_drop_ratio)
        if not self.df.empty and "TimeCreated" in self.df.columns:
            self.df["TimeCreated"] = pd.to_datetime(self.df["TimeCreated"], utc=True, errors="coerce")
            self.df = self.df.sort_values("TimeCreated").reset_index(drop=True)

    def detect_log_clearing(self) -> List[Dict[str, Any]]:
        """
        Detect event-log clearing (EID 1102 Security, EID 104 System).

        Returns
        -------
        List[dict]
            Findings including operator SID when present.
        """
        findings: List[Dict[str, Any]] = []
        if self.df.empty or "EventID" not in self.df.columns:
            return findings
        cleared = self.df[self.df["EventID"].astype(int).isin([1102, 104])]
        for _, row in cleared.iterrows():
            eid = int(row["EventID"])
            log_type = "Security" if eid == 1102 else "System"
            operator = row.get("SubjectUserName") or "-"
            sid = "-"
            if "SubjectUserSid" in row and str(row.get("SubjectUserSid", "-")) not in {"-", "nan", "None"}:
                sid = str(row.get("SubjectUserSid"))
            raw = row.get("RawData") if "RawData" in row else {}
            if isinstance(raw, dict):
                sid = sid if sid != "-" else str(raw.get("SubjectUserSid") or "-")
                operator = operator if operator not in {"-", None} else raw.get("SubjectUserName", operator)
            findings.append(
                self._row(
                    detection_type="Log Clearing",
                    event_id=eid,
                    timestamp=row.get("TimeCreated"),
                    evidence_detail=(
                        f"{log_type} event log cleared (Event ID {eid}) by operator "
                        f"{operator} SID={sid} at {row.get('TimeCreated')}"
                    ),
                    severity="High",
                    mitre_id="T1070",
                    extra={"operator": operator, "operator_sid": sid, "confidence": 1.0},
                )
            )
        return findings

    def detect_time_changes(self) -> List[Dict[str, Any]]:
        """
        Detect timestamp manipulation (EID 4616).

        Returns
        -------
        List[dict]
            Findings with old time, new time, delta, and process.
        """
        findings: List[Dict[str, Any]] = []
        if self.df.empty or "EventID" not in self.df.columns:
            return findings
        for _, row in self.df[self.df["EventID"].astype(int) == 4616].iterrows():
            raw = row.get("RawData") if "RawData" in row else {}
            if not isinstance(raw, dict):
                raw = {}
            old_time = row.get("OldTime") if "OldTime" in row else raw.get("PreviousTime") or raw.get("OldTime")
            new_time = row.get("NewTime") if "NewTime" in row else raw.get("NewTime")
            process = row.get("ProcessName") if "ProcessName" in row else raw.get("ProcessName", "-")
            delta = time_delta_seconds(old_time, new_time)
            findings.append(
                self._row(
                    detection_type="Timestamp Manipulation",
                    event_id=4616,
                    timestamp=row.get("TimeCreated"),
                    evidence_detail=(
                        f"System time changed (4616) by {row.get('SubjectUserName', 'Unknown')}: "
                        f"old={old_time} new={new_time} delta={delta:.1f}s process={process}"
                    ),
                    severity="High",
                    mitre_id="T1070.006",
                    extra={
                        "old_time": old_time,
                        "new_time": new_time,
                        "delta_seconds": delta,
                        "process": process,
                        "confidence": 0.95,
                    },
                )
            )
        return findings

    def detect_record_id_gaps(self, threshold: int = 1) -> List[Dict[str, Any]]:
        """
        Detect selective deletion via gaps in the EVTX RecordID sequence.

        Parameters
        ----------
        threshold : int
            Minimum gap size (exclusive of consecutive +1) to flag.
            ``threshold=1`` flags any missing id (diff > 1).

        Returns
        -------
        List[dict]
            One finding per gap.
        """
        findings: List[Dict[str, Any]] = []
        if self.df.empty or "RecordID" not in self.df.columns or len(self.df) < 2:
            return findings
        valid = self.df[pd.to_numeric(self.df["RecordID"], errors="coerce").fillna(0) > 0].copy()
        valid["RecordID"] = valid["RecordID"].astype(int)
        valid = valid.sort_values("RecordID").reset_index(drop=True)
        if len(valid) < 2:
            return findings
        rec_ids = valid["RecordID"].to_numpy()
        diffs = np.diff(rec_ids)
        for idx in np.where(diffs > threshold)[0]:
            gap_size = int(diffs[idx] - 1)
            before = valid.iloc[int(idx)]
            after = valid.iloc[int(idx) + 1]
            findings.append(
                self._row(
                    detection_type="RecordID Gap",
                    event_id=int(after.get("EventID", -1)),
                    timestamp=after.get("TimeCreated"),
                    evidence_detail=(
                        f"EVTX RecordID sequence gap of {gap_size} missing record(s) "
                        f"between ID #{int(before['RecordID'])} and #{int(after['RecordID'])} "
                        f"(possible selective deletion)"
                    ),
                    severity="High",
                    mitre_id="T1070.001",
                    extra={
                        "gap_size": gap_size,
                        "before_id": int(before["RecordID"]),
                        "after_id": int(after["RecordID"]),
                        "confidence": 0.90,
                        "anomaly": "Selective Record Deletion",
                    },
                )
            )
        return findings

    def detect_volume_drops(self, window_hours: int = 1, drop_ratio: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Flag a rolling 1-hour bucket whose count drops >80% vs the prior hour.

        Parameters
        ----------
        window_hours : int
            Bucket size in hours (contract default: 1).
        drop_ratio : float, optional
            Override of ``self.volume_drop_ratio`` (0.80 means "more than 80%").

        Returns
        -------
        List[dict]
            Volume-drop findings.
        """
        findings: List[Dict[str, Any]] = []
        ratio = self.volume_drop_ratio if drop_ratio is None else float(drop_ratio)
        if self.df.empty or "TimeCreated" not in self.df.columns or len(self.df) < 2:
            return findings
        work = self.df.dropna(subset=["TimeCreated"]).set_index("TimeCreated").sort_index()
        if work.empty:
            return findings
        rule = f"{int(window_hours)}h"
        try:
            hourly = work.resample(rule).size()
        except Exception:
            return findings
        if len(hourly) < 2:
            return findings
        counts = hourly.tolist()
        index = list(hourly.index)
        for i in range(1, len(counts)):
            prev, curr = int(counts[i - 1]), int(counts[i])
            if prev <= 0:
                continue
            drop = (prev - curr) / prev
            if drop > ratio:
                findings.append(
                    self._row(
                        detection_type="Log Volume Drop",
                        event_id=-1,
                        timestamp=index[i],
                        evidence_detail=(
                            f"Event volume dropped {drop:.0%} "
                            f"({curr} events) versus prior hour baseline of {prev} events "
                            f"(threshold {ratio:.0%})"
                        ),
                        severity="Medium",
                        mitre_id="T1070",
                        extra={
                            "prior_count": prev,
                            "current_count": curr,
                            "drop_ratio": drop,
                            "confidence": 0.80,
                        },
                    )
                )
        return findings

    def detect_sam_mismatch(self) -> List[Dict[str, Any]]:
        """
        Detect SAM account-creation time vs EID 4720 discrepancies.

        Returns
        -------
        List[dict]
            Mismatch findings.
        """
        findings: List[Dict[str, Any]] = []
        if self.df.empty or not self.sam_records:
            return findings
        creation = self.df[self.df["EventID"].astype(int) == 4720]
        evtx_creations = {}
        for _, row in creation.iterrows():
            uname = str(row.get("TargetUserName", "")).lower().strip()
            if uname and uname != "-":
                evtx_creations[uname] = row.get("TimeCreated")
        for sam_user in self.sam_records:
            uname = str(sam_user.get("Username", "")).lower().strip()
            sam_created = sam_user.get("CreationTime")
            if uname in evtx_creations and sam_created:
                ev_created = normalize_to_utc(evtx_creations[uname])
                sm_created = normalize_to_utc(sam_created)
                if abs(time_delta_seconds(ev_created, sm_created)) > 300:
                    findings.append(
                        self._row(
                            detection_type="SAM Record Mismatch",
                            event_id=4720,
                            timestamp=sm_created or ev_created,
                            evidence_detail=(
                                f"SAM creation timestamp for '{sam_user.get('Username')}' "
                                f"differs from Event 4720 by more than 5 minutes"
                            ),
                            severity="High",
                            mitre_id="T1070",
                            extra={"confidence": 0.88},
                        )
                    )
        return findings

    def run_all(self) -> List[Dict[str, Any]]:
        """
        Run every anti-forensic detector.

        Returns
        -------
        List[dict]
            Combined findings (contract schema + extra metadata).
        """
        findings: List[Dict[str, Any]] = []
        findings.extend(self.detect_log_clearing())
        findings.extend(self.detect_time_changes())
        findings.extend(self.detect_record_id_gaps())
        findings.extend(self.detect_volume_drops())
        findings.extend(self.detect_sam_mismatch())
        return findings

    def to_dataframe(self, findings: Optional[List[Dict[str, Any]]] = None) -> pd.DataFrame:
        """
        Materialise findings as a DataFrame with the contract columns first.

        Parameters
        ----------
        findings : list of dict, optional
            Findings to convert. Defaults to ``run_all()``.

        Returns
        -------
        pd.DataFrame
            Anti-forensic table.
        """
        rows = findings if findings is not None else self.run_all()
        if not rows:
            return pd.DataFrame(columns=OUTPUT_SCHEMA)
        return pd.DataFrame(rows)

    @staticmethod
    def _row(
        detection_type: str,
        event_id: int,
        timestamp,
        evidence_detail: str,
        severity: str,
        mitre_id: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        rec = {
            "detection_type": detection_type,
            "event_id": event_id,
            "timestamp": normalize_to_utc(timestamp),
            "evidence_detail": evidence_detail,
            "severity": severity,
            "anomaly": detection_type,
            "details": evidence_detail,
            "mitre_id": mitre_id,
            "confidence": (extra or {}).get("confidence", 0.8),
        }
        if extra:
            rec.update(extra)
        return rec
