"""
WinLogin Forensics - HTML Report Generator
=====================================================
Jinja2-based forensic report generation with executive summary, event statistics,
MITRE ATT&CK coverage, session analysis, anomaly findings, and integrity block.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .integrity import ChainOfCustody, ReportIntegrity, TOOL_NAME, TOOL_VERSION, utc_now_iso
from .mitre_mapper import build_coverage_matrix, coverage_summary, resolve_mitre_id


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

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}


@dataclass
class CaseInfo:
    case_number: str = ""
    investigator: str = ""
    organization: str = ""
    analysis_date: str = ""
    system_hostname: str = ""
    system_os: str = ""
    notes: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "case_number": self.case_number or "N/A",
            "investigator": self.investigator or "N/A",
            "organization": self.organization or "N/A",
            "analysis_date": self.analysis_date or utc_now_iso(),
            "system_hostname": self.system_hostname or "N/A",
            "system_os": self.system_os or "N/A",
            "notes": self.notes or "",
        }


@dataclass
class ReportData:
    """Container for all inputs required to generate a forensic report."""

    case: CaseInfo = field(default_factory=CaseInfo)
    events: Optional[pd.DataFrame] = None
    sessions: Optional[pd.DataFrame] = None
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    ml_results: Optional[Dict[str, Any]] = None
    source_files: List[Dict[str, str]] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeline_html: str = ""
    appendix_notes: str = ""


class HtmlReportGenerator:
    """Generates HTML forensic reports from parsed analysis data."""

    def __init__(self, template_dir: Optional[Union[str, Path]] = None):
        if template_dir is None:
            template_dir = Path(__file__).parent / "templates"
        self.template_dir = Path(template_dir)
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def build_context(self, data: ReportData) -> Dict[str, Any]:
        """Assemble the full Jinja2 template context from report data."""
        events_df = data.events if data.events is not None else pd.DataFrame()
        sessions_df = data.sessions if data.sessions is not None else pd.DataFrame()
        anomalies = list(data.anomalies or [])

        event_stats = self._compute_event_statistics(events_df)
        session_stats = self._compute_session_statistics(sessions_df)
        executive_summary = self._build_executive_summary(anomalies, event_stats, session_stats)
        mitre_matrix = build_coverage_matrix(anomalies)
        mitre_stats = coverage_summary(anomalies)
        anomaly_rows = self._format_anomalies(anomalies)
        events_table = self._format_events_table(events_df)
        sessions_table = self._format_sessions_table(sessions_df)

        time_range = self._time_range(events_df)

        return {
            "tool_name": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "generated_at": utc_now_iso(),
            "case": data.case.to_dict(),
            "executive_summary": executive_summary,
            "event_stats": event_stats,
            "session_stats": session_stats,
            "time_range": time_range,
            "mitre_matrix": mitre_matrix,
            "mitre_stats": mitre_stats,
            "anomalies": anomaly_rows,
            "anomaly_count": len(anomaly_rows),
            "sessions": sessions_table,
            "events": events_table,
            "events_total": len(events_df),
            "events_display_limit": min(len(events_df), 500),
            "ml_results": data.ml_results or {},
            "timeline_html": data.timeline_html,
            "appendix_notes": data.appendix_notes,
            "parameters": data.parameters,
            "source_files": data.source_files,
            "integrity": {},
            "chain_of_custody": {},
        }

    def generate_html(
        self,
        data: ReportData,
        output_path: Optional[Union[str, Path]] = None,
        sign: bool = False,
        timestamp: bool = False,
        operator: Optional[str] = None,
    ) -> str:
        """
        Render the full HTML report. Optionally writes to disk with integrity metadata.
        Returns the HTML string.
        """
        context = self.build_context(data)

        # Chain of custody
        coc = ChainOfCustody(operator=operator, parameters=data.parameters)
        for src in data.source_files:
            coc.source_files.append(src)
        context["chain_of_custody"] = coc.to_dict()

        template = self.env.get_template("report_template.html")
        html = template.render(**context)

        # Integrity block (computed after render so hash covers final output)
        integrity = ReportIntegrity(sign=sign, timestamp=timestamp)
        integrity_block = integrity.process(html)
        context["integrity"] = integrity_block

        html = template.render(**context)

        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(html, encoding="utf-8")
            coc.add_output_file(out, integrity_block["sha256"])
            coc.save(out.with_suffix(".coc.json"))

        return html

    def _compute_event_statistics(self, df: pd.DataFrame) -> Dict[str, Any]:
        if df.empty:
            return {
                "total": 0,
                "by_event_id": [],
                "by_category": [],
                "by_user": [],
                "by_logon_type": [],
            }

        by_event = (
            df.groupby("EventID").size().reset_index(name="count")
            .sort_values("count", ascending=False)
        )
        by_event["label"] = by_event["EventID"].astype(str)

        by_category = (
            df.groupby("Category").size().reset_index(name="count")
            .sort_values("count", ascending=False)
        ) if "Category" in df.columns else pd.DataFrame(columns=["Category", "count"])

        by_user = (
            df[df["TargetUserName"].notna() & (df["TargetUserName"] != "-")]
            .groupby("TargetUserName").size().reset_index(name="count")
            .sort_values("count", ascending=False).head(20)
        ) if "TargetUserName" in df.columns else pd.DataFrame(columns=["TargetUserName", "count"])

        by_logon = pd.DataFrame(columns=["LogonType", "count", "label"])
        if "LogonType" in df.columns:
            logon_df = df[df["LogonType"] >= 0]
            if not logon_df.empty:
                by_logon = (
                    logon_df.groupby("LogonType").size().reset_index(name="count")
                    .sort_values("count", ascending=False)
                )
                by_logon["label"] = by_logon["LogonType"].apply(
                    lambda x: LOGON_TYPE_NAMES.get(int(x), f"Type {x}")
                )

        return {
            "total": len(df),
            "by_event_id": by_event.to_dict("records"),
            "by_category": by_category.to_dict("records"),
            "by_user": by_user.to_dict("records"),
            "by_logon_type": by_logon.to_dict("records"),
        }

    def _compute_session_statistics(self, df: pd.DataFrame) -> Dict[str, Any]:
        if df.empty:
            return {"total": 0, "completed": 0, "orphaned": 0, "avg_duration_seconds": 0}

        total = len(df)
        completed = len(df[df["Status"].astype(str).str.contains("Completed", na=False)]) if "Status" in df.columns else 0
        orphaned = total - completed
        avg_dur = float(df["DurationSeconds"].mean()) if "DurationSeconds" in df.columns else 0.0

        return {
            "total": total,
            "completed": completed,
            "orphaned": orphaned,
            "avg_duration_seconds": round(avg_dur, 1),
        }

    def _build_executive_summary(
        self,
        anomalies: List[Dict[str, Any]],
        event_stats: Dict[str, Any],
        session_stats: Dict[str, Any],
    ) -> List[str]:
        bullets: List[str] = []

        total_events = event_stats.get("total", 0)
        bullets.append(
            f"Analysis covered {total_events:,} parsed authentication and security events."
        )

        total_sessions = session_stats.get("total", 0)
        orphaned = session_stats.get("orphaned", 0)
        if total_sessions:
            bullets.append(
                f"Session correlation identified {total_sessions} user sessions "
                f"({orphaned} without a recorded logoff)."
            )

        if not anomalies:
            bullets.append("No rule-based or ML anomalies were flagged during this analysis.")
            return bullets

        high = sum(1 for a in anomalies if str(a.get("severity", "")).lower() == "high")
        medium = sum(1 for a in anomalies if str(a.get("severity", "")).lower() == "medium")
        bullets.append(
            f"A total of {len(anomalies)} suspicious activities were flagged "
            f"({high} high severity, {medium} medium severity)."
        )

        sorted_anomalies = sorted(
            anomalies,
            key=lambda a: SEVERITY_ORDER.get(str(a.get("severity", "Unknown")), 3),
        )
        for finding in sorted_anomalies[:5]:
            name = finding.get("anomaly", "Unknown")
            details = str(finding.get("details", ""))[:120]
            mitre = resolve_mitre_id(finding)
            bullets.append(f"[{finding.get('severity', '?')}] {name} ({mitre}): {details}")

        return bullets

    def _format_anomalies(self, anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        rows = []
        for finding in sorted(
            anomalies,
            key=lambda a: (
                SEVERITY_ORDER.get(str(a.get("severity", "Unknown")), 3),
                str(a.get("timestamp", "")),
            ),
        ):
            ts = finding.get("timestamp", "")
            if hasattr(ts, "strftime"):
                ts = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
            rows.append({
                "anomaly": finding.get("anomaly", "Unknown"),
                "severity": finding.get("severity", "Unknown"),
                "mitre_id": resolve_mitre_id(finding),
                "timestamp": str(ts),
                "details": finding.get("details", ""),
                "confidence": finding.get("confidence", ""),
                "event_id": finding.get("event_id", ""),
                "shap": finding.get("shap", finding.get("shap_values", "")),
            })
        return rows

    def _format_events_table(self, df: pd.DataFrame, limit: int = 500) -> List[Dict[str, Any]]:
        if df.empty:
            return []

        display_cols = [
            "TimeCreated", "EventID", "Category", "Description",
            "TargetUserName", "IpAddress", "LogonType", "WorkstationName",
        ]
        cols = [c for c in display_cols if c in df.columns]
        subset = df[cols].head(limit)

        rows = []
        for _, row in subset.iterrows():
            record = {}
            for col in cols:
                val = row[col]
                if hasattr(val, "strftime"):
                    val = val.strftime("%Y-%m-%d %H:%M:%S UTC")
                elif col == "LogonType" and val is not None and val >= 0:
                    val = LOGON_TYPE_NAMES.get(int(val), val)
                record[col] = val
            rows.append(record)
        return rows

    def _format_sessions_table(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        if df.empty:
            return []

        rows = []
        for _, row in df.iterrows():
            start = row.get("StartTime", "")
            end = row.get("EndTime", "")
            if hasattr(start, "strftime"):
                start = start.strftime("%Y-%m-%d %H:%M:%S UTC")
            if end is not None and hasattr(end, "strftime"):
                end = end.strftime("%Y-%m-%d %H:%M:%S UTC")

            rows.append({
                "SessionID": row.get("SessionID", ""),
                "Username": row.get("Username", ""),
                "Domain": row.get("Domain", ""),
                "LogonTypeName": row.get("LogonTypeName", ""),
                "IpAddress": row.get("IpAddress", ""),
                "StartTime": start,
                "EndTime": end or "—",
                "DurationFormatted": row.get("DurationFormatted", ""),
                "Status": row.get("Status", ""),
            })
        return rows

    def _time_range(self, df: pd.DataFrame) -> Dict[str, str]:
        if df.empty or "TimeCreated" not in df.columns:
            return {"start": "N/A", "end": "N/A"}

        ts = pd.to_datetime(df["TimeCreated"], utc=True)
        return {
            "start": ts.min().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "end": ts.max().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }


def generate_report_html(
    data: ReportData,
    output_path: Union[str, Path],
    sign: bool = False,
    timestamp: bool = False,
    operator: Optional[str] = None,
) -> str:
    """Convenience function to generate and save an HTML report."""
    gen = HtmlReportGenerator()
    return gen.generate_html(data, output_path=output_path, sign=sign, timestamp=timestamp, operator=operator)
