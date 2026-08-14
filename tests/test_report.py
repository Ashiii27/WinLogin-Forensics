"""Phase 6 — HTML / PDF report generation tests."""

from __future__ import annotations

import json
from pathlib import Path

from src.parsers.evtx_parser import EvtxParser
from src.parsers.session_correlator import SessionCorrelator
from src.report.html_generator import CaseInfo, HtmlReportGenerator, ReportData
from src.report.integrity import ChainOfCustody, hash_file
from src.report.pdf_generator import PdfReportGenerator


def _sample_data() -> ReportData:
    events = EvtxParser().parse_records(
        [
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T09:00:00Z",
                "TargetUserName": "alice",
                "TargetLogonId": "0x1",
                "LogonType": 2,
                "IpAddress": "10.0.0.8",
                "WorkstationName": "WS1",
            },
            {
                "EventID": 4634,
                "TimeCreated": "2026-08-12T10:00:00Z",
                "TargetUserName": "alice",
                "TargetLogonId": "0x1",
                "LogonType": 2,
                "WorkstationName": "WS1",
            },
        ]
    )
    sessions = SessionCorrelator(events).correlate()
    anomalies = [
        {
            "anomaly": "Brute Force Attack",
            "severity": "High",
            "mitre_id": "T1110.001",
            "timestamp": "2026-08-12T02:14:00Z",
            "details": "6 failed logons",
            "confidence": 0.95,
            "shap_explanation": {"failed_logon_count_last_1h": 0.42, "hour_of_day": 0.11},
        }
    ]
    return ReportData(
        case=CaseInfo(case_number="CASE-001", investigator="Ashish", organization="CORP IR"),
        events=events,
        sessions=sessions,
        anomalies=anomalies,
        antiforensic=[
            {
                "detection_type": "Log Clearing",
                "event_id": 1102,
                "timestamp": "2026-08-12T02:40:00Z",
                "evidence_detail": "Security log cleared",
                "severity": "High",
            }
        ],
        registry={"sam": [{"RID": 500, "Username": "Administrator", "LastLogon": "2026-08-12", "LoginCount": 3, "Enabled": True}]},
        source_files=[],
    )


def test_html_report_renders(tmp_path: Path):
    data = _sample_data()
    out = tmp_path / "report.html"
    html = HtmlReportGenerator().generate_html(data, output_path=out, operator="examiner")
    assert out.exists()
    text = html.lower()
    assert "executive summary" in text
    assert "event statistics" in text
    assert "session" in text
    assert "anomaly" in text
    assert "t1110.001" in text
    assert "anti-forensic" in text
    assert "registry" in text
    assert "chain of custody" in text
    assert "shap" in text


def test_pdf_generated_and_sha256_logged(tmp_path: Path):
    data = _sample_data()
    coc = ChainOfCustody(operator="examiner", output_path=tmp_path)
    data.custody = coc
    pdf_path = tmp_path / "report.pdf"
    written = PdfReportGenerator().generate(data, pdf_path, operator="examiner", custody=coc)
    assert written.exists()
    assert written.stat().st_size > 0
    digest = hash_file(written)
    custody_path = tmp_path / "custody_log.json"
    assert custody_path.exists()
    payload = json.loads(custody_path.read_text(encoding="utf-8"))
    hashes = {f.get("sha256") for f in payload.get("output_files", [])}
    assert digest in hashes
    actions = " ".join(a.get("action", "") + a.get("detail", "") for a in payload.get("actions", []))
    assert "PDF" in actions or "pdf" in actions.lower() or digest in actions
