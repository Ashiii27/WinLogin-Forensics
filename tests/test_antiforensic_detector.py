"""Phase 2 — Anti-forensic detector tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from src.parsers.antiforensic_detector import OUTPUT_SCHEMA, AntiForensicDetector
from src.parsers.evtx_parser import EvtxParser


def _df(rows):
    return EvtxParser(include_unsupported=True).parse_records(rows)


def test_log_clearing_1102_and_104():
    df = _df(
        [
            {
                "EventID": 1102,
                "TimeCreated": "2026-08-12T02:40:00Z",
                "SubjectUserName": "Administrator",
                "SubjectUserSid": "S-1-5-21-1-2-3-500",
                "RecordID": 50,
            },
            {
                "EventID": 104,
                "TimeCreated": "2026-08-12T02:40:05Z",
                "SubjectUserName": "Administrator",
                "SubjectUserSid": "S-1-5-21-1-2-3-500",
                "RecordID": 51,
            },
        ]
    )
    findings = AntiForensicDetector(df).detect_log_clearing()
    types = {f["detection_type"] for f in findings}
    assert "Log Clearing" in types
    assert {f["event_id"] for f in findings} == {1102, 104}
    assert all("SID=" in f["evidence_detail"] for f in findings)
    for col in OUTPUT_SCHEMA:
        assert col in findings[0]


def test_timestamp_manipulation_4616():
    df = _df(
        [
            {
                "EventID": 4616,
                "TimeCreated": "2026-08-12T02:39:00Z",
                "SubjectUserName": "Administrator",
                "OldTime": "2026-08-12T02:39:00Z",
                "NewTime": "2026-08-11T02:39:00Z",
                "ProcessName": r"C:\Windows\System32\cmd.exe",
                "RecordID": 48,
            }
        ]
    )
    findings = AntiForensicDetector(df).detect_time_changes()
    assert len(findings) == 1
    assert findings[0]["detection_type"] == "Timestamp Manipulation"
    assert findings[0]["event_id"] == 4616
    assert "delta=" in findings[0]["evidence_detail"]
    assert "cmd.exe" in findings[0]["evidence_detail"]


def test_recordid_gap_detection():
    rows = []
    # Sequential 1..5 then jump to 10..12 — gap of 4 missing ids (6,7,8,9)
    for rid, minute in [(1, 0), (2, 1), (3, 2), (4, 3), (5, 4), (10, 5), (11, 6), (12, 7)]:
        rows.append(
            {
                "EventID": 4624,
                "TimeCreated": f"2026-08-12T10:{minute:02d}:00Z",
                "TargetUserName": "alice",
                "TargetLogonId": hex(rid),
                "RecordID": rid,
                "LogonType": 2,
                "WorkstationName": "WS",
            }
        )
    df = _df(rows)
    findings = AntiForensicDetector(df).detect_record_id_gaps()
    assert findings, "expected a RecordID gap finding"
    gap = findings[0]
    assert gap["detection_type"] in {"RecordID Gap", "Selective Record Deletion"}
    assert gap["gap_size"] == 4
    assert "#5" in gap["evidence_detail"] and "#10" in gap["evidence_detail"]


def test_volume_drop_flagged_on_fixture():
    base = datetime(2026, 8, 12, 10, 0, tzinfo=timezone.utc)
    rows = []
    # Hour 0: 20 events
    for i in range(20):
        rows.append(
            {
                "EventID": 4624,
                "TimeCreated": (base + timedelta(minutes=i * 2)).isoformat().replace("+00:00", "Z"),
                "TargetUserName": "alice",
                "TargetLogonId": hex(1000 + i),
                "RecordID": 100 + i,
                "LogonType": 2,
                "WorkstationName": "WS",
            }
        )
    # Hour 1: 3 events → 85% drop (> 80%)
    hour2 = base + timedelta(hours=1)
    for i in range(3):
        rows.append(
            {
                "EventID": 4624,
                "TimeCreated": (hour2 + timedelta(minutes=i * 5)).isoformat().replace("+00:00", "Z"),
                "TargetUserName": "alice",
                "TargetLogonId": hex(2000 + i),
                "RecordID": 200 + i,
                "LogonType": 2,
                "WorkstationName": "WS",
            }
        )
    df = _df(rows)
    findings = AntiForensicDetector(df).detect_volume_drops()
    assert findings, "expected a volume-drop finding"
    assert findings[0]["detection_type"] == "Log Volume Drop"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["drop_ratio"] > 0.80


def test_run_all_and_dataframe_schema():
    df = _df(
        [
            {
                "EventID": 1102,
                "TimeCreated": "2026-08-12T02:40:00Z",
                "SubjectUserName": "Administrator",
                "SubjectUserSid": "S-1-5-18",
                "RecordID": 1,
            },
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T02:41:00Z",
                "TargetUserName": "alice",
                "RecordID": 5,
                "TargetLogonId": "0x1",
            },
        ]
    )
    det = AntiForensicDetector(df)
    table = det.to_dataframe()
    for col in OUTPUT_SCHEMA:
        assert col in table.columns
    assert not table.empty
