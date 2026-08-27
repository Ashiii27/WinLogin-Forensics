"""Phase 4 — Sysmon parser + session correlator linkage tests."""

from __future__ import annotations

from pathlib import Path

from src.analysis.correlator import ActivityCorrelator
from src.parsers.evtx_parser import EvtxParser
from src.parsers.session_correlator import SessionCorrelator
from src.parsers.sysmon_parser import SYSMON_EVENT_IDS, SysmonParser


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sysmon" / "sysmon_events.json"


def test_sysmon_parses_required_event_ids():
    df = SysmonParser(FIXTURE).parse()
    assert not df.empty
    ids = set(df["EventID"].astype(int))
    assert ids == {1, 3, 11, 22}
    eid1 = df[df["EventID"] == 1].iloc[0]
    assert eid1["ProcessId"] == "4124"
    assert eid1["ParentProcessId"] == "880"
    assert "whoami" in str(eid1["CommandLine"])
    assert eid1["User"]
    assert eid1["Hashes"]
    assert eid1["UtcTime"] is not None
    eid3 = df[df["EventID"] == 3].iloc[0]
    assert eid3["DestinationIp"] == "185.220.101.5"
    assert str(eid3["DestinationPort"]) == "443"
    assert eid3["Protocol"]
    eid11 = df[df["EventID"] == 11].iloc[0]
    assert "payload.exe" in str(eid11["TargetFilename"])
    eid22 = df[df["EventID"] == 22].iloc[0]
    assert eid22["QueryName"] == "c2.badactor.example"
    assert eid22["QueryResults"]


def test_correlator_links_sysmon_to_session():
    events = EvtxParser().parse_records(
        [
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T11:20:00Z",
                "TargetUserName": "Administrator",
                "TargetLogonId": "0xabc",
                "LogonType": 10,
                "WorkstationName": "DC01",
                "IpAddress": "10.0.0.15",
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
    assert len(sessions) == 1
    sid = sessions.iloc[0]["SessionID"]

    sysmon = SysmonParser(FIXTURE).parse()
    enriched = ActivityCorrelator(sessions, sysmon=sysmon).correlate()
    row = enriched.iloc[0]
    assert row["SessionID"] == sid
    assert row["linked_processes"], "expected Sysmon EID 1 linked to the session"
    assert any(p["ProcessId"] == "4124" for p in row["linked_processes"])
    assert row["linked_network"], "expected network/DNS/file events via ProcessId"
    kinds = {n["kind"] for n in row["linked_network"]}
    assert "network" in kinds
    assert "dns" in kinds


def test_sysmon_catalogue():
    assert set(SYSMON_EVENT_IDS) == {1, 3, 11, 22}


def test_sysmon_evtx_unavailable(monkeypatch, sample_security_evtx: Path):
    import src.parsers.sysmon_parser as mod
    monkeypatch.setattr(mod, "EVTX_AVAILABLE", False)
    df = mod.SysmonParser(sample_security_evtx).parse()
    assert df.empty
