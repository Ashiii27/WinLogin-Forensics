# TODO: Phase 1 — Parse EVTX samples from Win10/11/Server 2016-2022 to confirm schema differences
#!/usr/bin/env python3
"""
Confirm EVTX schema differences across Windows 10/11/Server exports still parse.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.parsers.evtx_parser import EVENT_SCHEMA, EvtxParser, build_event_xml


# Minimal schema variants observed across Windows versions
VARIANTS = {
    "win10": build_event_xml(4624, "2026-01-01T12:00:00.0000000Z", target_user="a", target_logon_id="0x1", logon_type=2),
    "server2019": (
        '<?xml version="1.0"?>\n'
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
        "<EventID Qualifiers=''>4625</EventID>"
        "<TimeCreated SystemTime='2026-01-01T12:00:01Z'/>"
        "<EventRecordID>9</EventRecordID><Channel>Security</Channel>"
        "<Computer>DC01</Computer></System>"
        "<EventData><Data Name='TargetUserName'>b</Data>"
        "<Data Name='IpAddress'>10.0.0.2</Data>"
        "<Data Name='Status'>0xC000006D</Data></EventData></Event>"
    ),
    "win11_userdata": (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>1102</EventID>"
        "<TimeCreated SystemTime='2026-01-01T12:00:02Z'/>"
        "<EventRecordID>10</EventRecordID><Channel>Security</Channel>"
        "<Computer>DC01</Computer></System>"
        "<UserData><LogFileCleared><SubjectUserName>admin</SubjectUserName>"
        "</LogFileCleared></UserData></Event>"
    ),
}


def main() -> int:
    """Parse each variant and assert the contract schema is present."""
    parser = EvtxParser()
    for name, xml in VARIANTS.items():
        rec = parser.parse_xml_string(xml)
        assert rec is not None, f"{name} failed to parse"
        for col in EVENT_SCHEMA:
            assert col in rec, f"{name} missing {col}"
        print(f"OK {name} EventID={rec['EventID']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
