"""Phase 3 — Registry parser tests."""

from __future__ import annotations

from pathlib import Path

from src.parsers.registry_parser import RegistryParser, parse_userassist_value
from src.utils.helpers import rot13_decode


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "registry"


def test_sam_parser_extracts_account_metadata():
    recs = RegistryParser(FIXTURES / "sam_accounts.json").parse_sam()
    assert recs, "expected SAM accounts from fixture"
    by_name = {r["Username"]: r for r in recs}
    admin = by_name["Administrator"]
    assert admin["RID"] == 500
    assert admin["LoginCount"] == 42
    assert admin["Enabled"] is True
    assert admin["LastLogon"] is not None or admin.get("LastLogon")
    guest = by_name["Guest"]
    assert guest["RID"] == 501
    assert guest["Enabled"] is False


def test_userassist_rot13_decode():
    encoded = "P:\\Jvaqbjf\\flfgrz32\\pzq.rkr"
    decoded = rot13_decode(encoded)
    assert decoded.lower().endswith("cmd.exe")
    assert "windows" in decoded.lower()
    assert "system32" in decoded.lower()

    anydesk = rot13_decode("P:\\Cebtenz Svyrf\\NalQrfx\\NalQrfx.rkr")
    assert "AnyDesk" in anydesk or "anydesk" in anydesk.lower()


def test_parse_userassist_fixture_decodes_paths():
    rows = RegistryParser(FIXTURES / "userassist.json").parse_userassist()
    assert len(rows) == 2
    decoded = {r["DecodedPath"] for r in rows}
    assert any("cmd.exe" in d.lower() for d in decoded)
    assert any("anydesk" in d.lower() for d in decoded)
    assert all(int(r["RunCount"]) > 0 for r in rows)


def test_parse_userassist_value_blob():
    # Craft a 72-byte Win7+ UserAssist blob: run count 7 at offset 4,
    # FILETIME at offset 60 (2026-08-12 roughly — any non-zero ticks).
    blob = bytearray(72)
    blob[4:8] = (7).to_bytes(4, "little")
    # 2026-08-12 00:00:00 UTC as FILETIME
    # ticks = (unix + 11644473600) * 10_000_000
    import datetime

    unix = datetime.datetime(2026, 8, 12, tzinfo=datetime.timezone.utc).timestamp()
    ticks = int((unix + 11644473600) * 10_000_000)
    blob[60:68] = ticks.to_bytes(8, "little")
    count, last = parse_userassist_value(bytes(blob))
    assert count == 7
    assert last is not None
    assert last.year == 2026


def test_run_keys_and_remote_access():
    parser = RegistryParser(FIXTURES / "run_keys.json")
    keys = parser.parse_run_keys()
    assert any(k["ValueName"] == "AnyDesk" for k in keys)
    tools = parser.parse_remote_access_tools()
    names = {t["ToolName"] for t in tools}
    assert "AnyDesk" in names
    assert "TeamViewer" in names


def test_missing_hive_returns_empty():
    parser = RegistryParser(None)
    assert parser.parse_sam() == []
    assert parser.parse_userassist() == []
    assert parser.parse_run_keys() == []
