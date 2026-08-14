"""Rule-based anomaly detector tests."""

from __future__ import annotations

from src.analysis.anomaly_detector import AnomalyDetector
from src.parsers.evtx_parser import EvtxParser
from src.parsers.session_correlator import SessionCorrelator


def test_brute_force_and_kerberoasting():
    events = EvtxParser().parse_records(
        [
            *[
                {
                    "EventID": 4625,
                    "TimeCreated": f"2026-08-12T10:00:{i:02d}Z",
                    "TargetUserName": "Administrator",
                    "IpAddress": "1.2.3.4",
                    "LogonType": 10,
                    "TargetLogonId": "0x0",
                    "WorkstationName": "X",
                    "Status": "0xC000006D",
                }
                for i in range(6)
            ],
            {
                "EventID": 4769,
                "TimeCreated": "2026-08-12T10:05:00Z",
                "TargetUserName": "Administrator",
                "ServiceName": "MSSQLSvc/sql",
                "TicketEncryptionType": "0x17",
                "IpAddress": "1.2.3.4",
                "WorkstationName": "X",
            },
        ]
    )
    findings = AnomalyDetector(events).detect()
    names = {f["anomaly"] for f in findings}
    assert "Brute Force Attack" in names
    assert "Kerberoasting" in names
    assert any(f["mitre_id"] == "T1110.001" for f in findings)
    assert any(f["mitre_id"] == "T1558.003" for f in findings)
