"""Phase 0 — EVTX parser and MITRE mapping tests."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from src.parsers.evtx_parser import (
    EVENT_SCHEMA,
    SUPPORTED_EVENT_IDS,
    EvtxParser,
    build_event_xml,
    parse_evtx,
)
from src.report.mitre_mapper import (
    MITRE_EVENT_RULES,
    lookup_rule,
    lookup_technique_id,
)


CONTRACT_EVENT_IDS = {
    4624,
    4625,
    4634,
    4647,
    4648,
    4672,
    4720,
    4722,
    4723,
    4724,
    4725,
    4726,
    4728,
    4732,
    4740,
    4756,
    4767,
    4768,
    4769,
    4771,
    4776,
    4698,
    7045,
    1102,
    104,
    4616,
}


def test_supported_catalogue_covers_contract_ids():
    missing = CONTRACT_EVENT_IDS - set(SUPPORTED_EVENT_IDS)
    assert not missing, f"Missing Event IDs: {missing}"


def test_parse_sample_security_xml_nonzero(sample_security_xml: Path):
    df = EvtxParser(sample_security_xml).parse()
    assert isinstance(df, pd.DataFrame)
    assert df.shape[0] > 0
    assert df.shape[1] >= len(EVENT_SCHEMA)


def test_dataframe_has_contract_schema(sample_security_xml: Path):
    df = parse_evtx(sample_security_xml)
    for col in EVENT_SCHEMA:
        assert col in df.columns, f"missing column {col}"


def test_core_and_extended_event_ids_parsed(sample_security_xml: Path):
    df = EvtxParser(sample_security_xml).parse()
    parsed_ids = set(df["EventID"].astype(int).tolist())
    missing = CONTRACT_EVENT_IDS - parsed_ids
    assert not missing, f"Fixture did not yield Event IDs: {missing}"


def test_4624_fields_extracted(sample_security_xml: Path):
    df = EvtxParser(sample_security_xml).parse()
    row = df[df["EventID"] == 4624].iloc[0]
    assert row["TargetUserName"] == "Ashish"
    assert row["TargetLogonId"] == "0x1a2b3c"
    assert int(row["LogonType"]) == 2
    assert row["IpAddress"] == "192.168.1.50"
    assert str(row["IpPort"]) == "49821"
    assert row["WorkstationName"] == "WORKSTATION-07"
    assert row["raw_xml"] and "<Event" in str(row["raw_xml"])


def test_parse_in_memory_xml_string():
    xml = build_event_xml(
        4624,
        "2026-08-12T08:00:00.0000000Z",
        record_id=42,
        target_user="alice",
        target_logon_id="0xabc",
        logon_type=10,
        ip_address="10.0.0.8",
        ip_port="3389",
        workstation="JUMP-01",
        status="0x0",
    )
    rec = EvtxParser().parse_xml_string(xml)
    assert rec is not None
    assert rec["EventID"] == 4624
    assert rec["TargetUserName"] == "alice"
    assert rec["TargetLogonId"] == "0xabc"
    assert rec["LogonType"] == 10
    assert rec["IpAddress"] == "10.0.0.8"


def test_parse_records_json_like():
    records = [
        {
            "EventID": 4625,
            "TimeCreated": "2026-08-12T01:00:00Z",
            "SubjectUserName": "-",
            "TargetUserName": "bob",
            "TargetLogonId": "0x0",
            "LogonType": 3,
            "IpAddress": "1.2.3.4",
            "IpPort": "445",
            "WorkstationName": "EVIL",
            "Status": "0xC000006D",
        }
    ]
    df = EvtxParser().parse_records(records)
    assert df.shape[0] == 1
    assert int(df.iloc[0]["EventID"]) == 4625
    assert df.iloc[0]["TargetUserName"] == "bob"


def test_parse_directory(tmp_path: Path, sample_security_xml: Path):
    dest = tmp_path / "logs"
    dest.mkdir()
    (dest / "a.xml").write_text(sample_security_xml.read_text(encoding="utf-8"), encoding="utf-8")
    df = EvtxParser().parse_directory(dest)
    assert df.shape[0] > 0


def test_unsupported_event_filtered_by_default():
    xml = build_event_xml(9999, "2026-08-12T00:00:00Z", target_user="x")
    assert EvtxParser().parse_xml_string(xml) is None
    rec = EvtxParser(include_unsupported=True).parse_xml_string(xml)
    assert rec is not None
    assert rec["EventID"] == 9999


def test_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        EvtxParser(tmp_path / "nope.evtx").parse()


def test_parse_binary_evtx_with_rust_parser(sample_security_evtx: Path):
    df = EvtxParser(sample_security_evtx, include_unsupported=True).parse()
    assert isinstance(df, pd.DataFrame)
    assert df.shape[0] > 0
    for col in EVENT_SCHEMA:
        assert col in df.columns


def test_parse_binary_evtx_read_only_false(sample_security_evtx: Path):
    df = EvtxParser(sample_security_evtx, read_only=False, include_unsupported=True).parse()
    assert isinstance(df, pd.DataFrame)
    assert df.shape[0] > 0


def test_evtx_parser_unavailable_raises(monkeypatch, sample_security_evtx: Path):
    import src.parsers.evtx_parser as mod
    monkeypatch.setattr(mod, "EVTX_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="evtx is not installed"):
        EvtxParser(sample_security_evtx).parse()


@pytest.mark.parametrize(
    "rule,technique",
    [
        ("Repeated 4625", "T1110.001"),
        ("Pass-the-Hash pattern", "T1550.002"),
        ("Kerberoasting (4769)", "T1558.003"),
        ("Orphaned privileged session", "T1078"),
        ("Log clearing (1102, 104)", "T1070"),
    ],
)
def test_mitre_lookup_contract_table(rule: str, technique: str):
    assert lookup_technique_id(rule) == technique
    row = lookup_rule(rule)
    assert row is not None
    assert row["technique_id"] == technique
    assert row["name"]
    assert MITRE_EVENT_RULES[rule]["technique_id"] == technique


def test_mitre_lookup_aliases():
    assert lookup_technique_id("brute force") == "T1110.001"
    assert lookup_technique_id("kerberoasting") == "T1558.003"
    assert lookup_technique_id("log clearing") == "T1070"
