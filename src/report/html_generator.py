"""
WinLogin Forensics - HTML Report Generator
=====================================================
Jinja2-based forensic report generation with executive summary, event statistics,
MITRE ATT&CK coverage, session analysis, anomaly findings, and integrity block.

Fixes applied (v1.0.1):
  - Events table now filters to supported Event IDs only (drops noisy 5156/5158/4688 rows)
  - LogonType -1 displays as "—" instead of the raw integer
  - 1102 (audit log cleared) and 104 (system log cleared) are surfaced as High findings
  - System hostname extracted from EVTX Computer field when available
  - HTML activity timeline added to report context
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

# Human-readable names for every event ID the tool supports.
# Used to annotate the stats table and the raw events table.
EVENT_ID_NAMES: Dict[int, str] = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4634: "Account Logoff",
    4647: "User-Initiated Logoff",
    4648: "Logon w/ Explicit Credentials",
    4672: "Special Privileges Assigned",
    4778: "RDP Session Reconnected",
    4779: "RDP Session Disconnected",
    4800: "Workstation Locked",
    4801: "Workstation Unlocked",
    4768: "Kerberos TGT Requested",
    4769: "Kerberos Service Ticket Requested",
    4771: "Kerberos Pre-Auth Failed",
    4776: "NTLM Credential Validation",
    4720: "User Account Created",
    4722: "User Account Enabled",
    4723: "Password Change Attempted",
    4724: "Password Reset Attempted",
    4725: "User Account Disabled",
    4726: "User Account Deleted",
    4728: "Member Added to Global Group",
    4732: "Member Added to Local Group",
    4740: "User Account Locked Out",
    4756: "Member Added to Universal Group",
    4767: "User Account Unlocked",
    4698: "Scheduled Task Created",
    7045: "New Service Installed",
    1102: "Security Audit Log Cleared",
    104:  "System Log Cleared",
    4616: "System Time Changed",
}

# Event IDs the parser actually enriches — used to filter the raw events table.
# Unsupported IDs (5156, 5158, 4688, 5145, …) are excluded from display so the
# analyst sees only meaningful rows.
SUPPORTED_EVENT_IDS = {
    4624, 4625, 4634, 4647, 4648, 4672, 4778, 4779, 4800, 4801,
    4768, 4769, 4771, 4776,
    4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4740, 4756, 4767,
    4698, 7045,
    1102, 104, 4616,
}

# Anti-forensic event IDs that must always appear as findings even when no
# anomaly detector explicitly fires on them.
ANTI_FORENSIC_EVENT_IDS = {
    1102: ("Security Audit Log Cleared", "T1070.001", "High",
           "Security audit log was cleared (Event 1102) — possible evidence destruction"),
    104:  ("System Log Cleared", "T1070.001", "High",
           "System event log was cleared (Event 104) — possible evidence destruction"),
    4616: ("System Time Changed", "T1070.006", "High",
           "System time was modified (Event 4616) — possible timestamp manipulation"),
}


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
    antiforensic: List[Dict[str, Any]] = field(default_factory=list)
    registry: Dict[str, Any] = field(default_factory=dict)
    custody: Optional[Any] = None


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

        # FIX: inject anti-forensic events as findings before building context
        anomalies = self._inject_antiforensic_findings(list(data.anomalies or []), events_df)

        event_stats = self._compute_event_statistics(events_df)
        session_stats = self._compute_session_statistics(sessions_df)
        executive_summary = self._build_executive_summary(anomalies, event_stats, session_stats)
        mitre_matrix = build_coverage_matrix(anomalies)
        mitre_stats = coverage_summary(anomalies)
        anomaly_rows = self._format_anomalies(anomalies)

        # FIX: filter events table to supported event IDs only
        events_table = self._format_events_table(events_df)
        sessions_table = self._format_sessions_table(sessions_df)

        time_range = self._time_range(events_df)

        # FIX: extract hostname from events if not provided in case info
        case_dict = data.case.to_dict()
        if case_dict["system_hostname"] == "N/A":
            hostname = self._extract_hostname(events_df)
            if hostname:
                case_dict["system_hostname"] = hostname

        # FIX: build activity timeline HTML
        timeline_html = data.timeline_html or self._build_timeline_html(events_df, anomalies)

        return {
            "tool_name": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "generated_at": utc_now_iso(),
            "case": case_dict,
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
            "events_display_limit": len(events_table),
            "ml_results": data.ml_results or {},
            "timeline_html": timeline_html,
            "appendix_notes": data.appendix_notes,
            "parameters": data.parameters,
            "source_files": data.source_files,
            "integrity": {},
            "chain_of_custody": {},
            "antiforensic": data.antiforensic or [],
            "registry": data.registry or {},
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

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _inject_antiforensic_findings(
        self,
        anomalies: List[Dict[str, Any]],
        events_df: pd.DataFrame,
    ) -> List[Dict[str, Any]]:
        """
        FIX: Ensure 1102, 104, and 4616 always produce High findings.

        The anomaly detector has no dedicated anti-forensic rule, so these
        events were previously only visible in the raw events table. This
        method checks the events DataFrame for each anti-forensic event ID
        and injects a finding for each occurrence that isn't already covered
        by an existing anomaly.
        """
        if events_df.empty or "EventID" not in events_df.columns:
            return anomalies

        existing_eids = {int(a.get("event_id", -1)) for a in anomalies}

        for eid, (name, mitre, severity, base_detail) in ANTI_FORENSIC_EVENT_IDS.items():
            if eid in existing_eids:
                continue  # already flagged by detector

            af_rows = events_df[events_df["EventID"].astype(int) == eid]
            for _, row in af_rows.iterrows():
                ts = row.get("TimeCreated")
                user = str(row.get("TargetUserName") or row.get("SubjectUserName") or "-")
                detail = base_detail
                if user not in {"-", "", "None"}:
                    detail = f"{base_detail} by {user}"
                anomalies.append({
                    "anomaly": name,
                    "detection_type": name,
                    "mitre_id": mitre,
                    "severity": severity,
                    "timestamp": ts,
                    "details": detail,
                    "evidence_detail": detail,
                    "confidence": 1.0,
                    "event_id": eid,
                    "rule": name,
                })

        return anomalies

    def _extract_hostname(self, df: pd.DataFrame) -> str:
        """
        FIX: Pull the Computer field from the events DataFrame if available.
        The EVTX System element contains a <Computer> tag that the parser
        stores in the 'Computer' column when present.
        """
        if df.empty:
            return ""
        for col in ("Computer", "ComputerName", "Hostname"):
            if col in df.columns:
                vals = df[col].dropna()
                vals = vals[vals.astype(str).str.strip().str.lower().isin({"", "-", "none"}) == False]
                if not vals.empty:
                    return str(vals.iloc[0])
        return ""

    def _build_timeline_html(
        self,
        events_df: pd.DataFrame,
        anomalies: List[Dict[str, Any]],
    ) -> str:
        """
        FIX: Generate a compact HTML bar-chart timeline of event activity by hour.

        Buckets events into hourly bins and renders a visual bar chart so
        analysts can immediately see quiet periods and bursts. Anomaly
        timestamps are overlaid as red markers.
        """
        if events_df.empty or "TimeCreated" not in events_df.columns:
            return ""

        ts_series = pd.to_datetime(events_df["TimeCreated"], utc=True, errors="coerce").dropna()
        if ts_series.empty:
            return ""

        # Hourly bucketing
        hourly = ts_series.dt.floor("h").value_counts().sort_index()
        if hourly.empty:
            return ""

        max_count = int(hourly.max())
        if max_count == 0:
            return ""

        # Collect anomaly hours for red-dot overlay
        anomaly_hours: set = set()
        for a in anomalies:
            ats = a.get("timestamp")
            if ats is not None:
                try:
                    ats_pd = pd.Timestamp(ats, tz="UTC") if not hasattr(ats, "floor") else ats
                    anomaly_hours.add(ats_pd.floor("h"))
                except Exception:
                    pass

        # Build SVG bar chart
        bar_w = 12
        gap = 2
        chart_h = 80
        padding_left = 40
        padding_bottom = 30

        n = len(hourly)
        svg_w = padding_left + n * (bar_w + gap) + 10
        svg_h = chart_h + padding_bottom + 10

        bars = []
        labels = []
        dots = []

        for i, (hour, count) in enumerate(hourly.items()):
            x = padding_left + i * (bar_w + gap)
            bar_h = max(2, int((count / max_count) * chart_h))
            y = chart_h - bar_h + 10
            is_anomaly = hour in anomaly_hours
            fill = "#dc2626" if is_anomaly else "#2563eb"
            bars.append(
                f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bar_h}" '
                f'fill="{fill}" opacity="0.85">'
                f'<title>{hour.strftime("%Y-%m-%d %H:00 UTC")}: {count} events</title>'
                f'</rect>'
            )
            if i % max(1, n // 6) == 0:
                label = hour.strftime("%m-%d %H:00")
                labels.append(
                    f'<text x="{x + bar_w // 2}" y="{chart_h + padding_bottom}" '
                    f'font-size="7" text-anchor="middle" fill="#64748b" '
                    f'transform="rotate(-30, {x + bar_w // 2}, {chart_h + padding_bottom})">'
                    f'{label}</text>'
                )

        # Y-axis label
        y_label = (
            f'<text x="10" y="{chart_h // 2 + 10}" font-size="8" fill="#64748b" '
            f'transform="rotate(-90, 10, {chart_h // 2 + 10})">Events/hr</text>'
        )
        max_label = (
            f'<text x="{padding_left - 2}" y="14" font-size="7" fill="#64748b" '
            f'text-anchor="end">{max_count}</text>'
        )

        # Legend
        legend = (
            f'<rect x="{padding_left}" y="0" width="8" height="8" fill="#2563eb"/>'
            f'<text x="{padding_left + 10}" y="8" font-size="7" fill="#64748b">Normal</text>'
            f'<rect x="{padding_left + 55}" y="0" width="8" height="8" fill="#dc2626"/>'
            f'<text x="{padding_left + 65}" y="8" font-size="7" fill="#64748b">Anomaly hour</text>'
        )

        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{svg_w}" height="{svg_h}" '
            f'style="max-width:100%;overflow-x:auto;">'
            + y_label + max_label + legend
            + "".join(bars)
            + "".join(labels)
            + "</svg>"
        )

        return (
            '<div style="overflow-x:auto;margin-bottom:12px;">'
            + svg
            + "</div>"
        )

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
        by_event["name"] = by_event["EventID"].apply(
            lambda eid: EVENT_ID_NAMES.get(int(eid), "—")
        )

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
        status = df["Status"].astype(str).str.lower() if "Status" in df.columns else pd.Series(dtype=str)
        completed = int(status.str.contains("closed|completed").sum()) if len(status) else 0
        orphaned = int(status.str.contains("orphan").sum()) if len(status) else max(0, total - completed)
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
                "shap": finding.get("shap_explanation") or finding.get("shap") or finding.get("shap_values") or {},
            })
        return rows

    def _format_events_table(self, df: pd.DataFrame, limit: int = 500) -> List[Dict[str, Any]]:
        """
        FIX: Filter to supported event IDs only before rendering.

        Rows with unsupported event IDs (e.g. 5156, 5158, 4688) contain no
        enriched fields and only add noise to the analyst view. They are
        still counted in event_stats (which uses the full DataFrame) but are
        excluded from the display table.
        """
        if df.empty:
            return []

        # Filter to supported event IDs
        filtered = df[df["EventID"].astype(int).isin(SUPPORTED_EVENT_IDS)].copy()

        display_cols = [
            "TimeCreated", "EventID", "EventName", "Category", "Description",
            "TargetUserName", "IpAddress", "LogonType", "WorkstationName",
        ]
        # Inject a friendly name column derived from EventID
        filtered["EventName"] = filtered["EventID"].apply(
            lambda eid: EVENT_ID_NAMES.get(int(eid), "—")
        )

        cols = [c for c in display_cols if c in filtered.columns]
        subset = filtered[cols].head(limit)

        rows = []
        for _, row in subset.iterrows():
            record = {}
            for col in cols:
                val = row[col]
                try:
                    is_na = pd.isna(val)
                except (TypeError, ValueError):
                    is_na = False

                if hasattr(val, "strftime") and not is_na:
                    val = val.strftime("%Y-%m-%d %H:%M:%S UTC")
                elif is_na:
                    val = "—"
                elif col == "LogonType":
                    # FIX: show "—" instead of -1 for events with no logon type
                    try:
                        lt = int(val)
                    except (TypeError, ValueError):
                        lt = -1
                    if lt < 0:
                        val = "—"
                    else:
                        val = LOGON_TYPE_NAMES.get(lt, str(lt))
                record[col] = val
            rows.append(record)
        return rows

    def _format_sessions_table(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        if df.empty:
            return []

        rows = []
        for _, row in df.iterrows():
            start = row.get("LogonTime", row.get("StartTime", ""))
            end = row.get("LogoffTime", row.get("EndTime", ""))

            if hasattr(start, "strftime") and not pd.isna(start):
                start = start.strftime("%Y-%m-%d %H:%M:%S UTC")
            elif pd.isna(start):
                start = "—"

            if hasattr(end, "strftime") and not pd.isna(end):
                end = end.strftime("%Y-%m-%d %H:%M:%S UTC")
            elif pd.isna(end) or end is None:
                end = "—"

            rows.append({
                "SessionID": row.get("SessionID", ""),
                "Username": row.get("Username", ""),
                "Domain": row.get("Domain", ""),
                "LogonTypeName": row.get("LogonTypeName", ""),
                "IpAddress": row.get("IpAddress", ""),
                "StartTime": start,
                "EndTime": end,
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