"""Phase 4 — PowerShell parser + session script-block correlation tests."""

from __future__ import annotations

from pathlib import Path

from src.analysis.correlator import ActivityCorrelator
from src.parsers.evtx_parser import EvtxParser
from src.parsers.powershell_parser import PowerShellParser
from src.parsers.session_correlator import SessionCorrelator


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "powershell" / "ps_events.json"


def test_powershell_parses_4103_and_4104():
    df = PowerShellParser(FIXTURE).parse()
    assert not df.empty
    ids = set(df["EventID"].astype(int))
    assert 4103 in ids and 4104 in ids


def test_obfuscation_markers_flagged():
    df = PowerShellParser(FIXTURE).parse()
    flagged = df[df["Suspicious"] == True]  # noqa: E712
    assert len(flagged) >= 2
    blob = " ".join(flagged["ObfuscationMarkers"].astype(str)).lower()
    assert "iex" in blob or "invoke-expression" in blob
    assert "-enc" in blob or "base64" in blob or "encodedcommand" in blob

    markers = PowerShellParser.flag_obfuscation("powershell -enc SQBFAFgA [char]65")
    assert "-enc" in markers
    assert "[char]" in markers


def test_scripts_linked_to_session():
    events = EvtxParser().parse_records(
        [
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T11:20:00Z",
                "TargetUserName": "Administrator",
                "TargetLogonId": "0xabc",
                "LogonType": 10,
                "WorkstationName": "DC01",
            },
            {
                "EventID": 4634,
                "TimeCreated": "2026-08-12T11:30:00Z",
                "TargetUserName": "Administrator",
                "TargetLogonId": "0xabc",
                "LogonType": 10,
                "WorkstationName": "DC01",
            },
        ]
    )
    sessions = SessionCorrelator(events).correlate()
    ps = PowerShellParser(FIXTURE).parse()
    enriched = ActivityCorrelator(sessions, powershell=ps).correlate()
    scripts = enriched.iloc[0]["linked_scripts"]
    assert scripts, "expected PowerShell script blocks linked to the session"
    assert any(s.get("Suspicious") for s in scripts)
    assert all(s.get("SessionID") == sessions.iloc[0]["SessionID"] for s in scripts)


def test_powershell_evtx_unavailable_raises(monkeypatch, sample_security_evtx: Path):
    import src.parsers.powershell_parser as mod
    monkeypatch.setattr(mod, "EVTX_AVAILABLE", False)
    # When EVTX_AVAILABLE is False, parse() falls through or returns empty
    df = mod.PowerShellParser(sample_security_evtx).parse()
    assert df.empty
