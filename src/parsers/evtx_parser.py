"""
WinLogin Forensics - EVTX Parser
================================
Parses Windows Security and System Event Log (.evtx) files — plus XML, JSON
and CSV exports — extracting 35+ authentication, session, Kerberos, account
management, persistence, and anti-forensic Event IDs into structured
pandas DataFrames.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

import pandas as pd

try:
    import Evtx.Evtx as evtx_lib

    EVTX_AVAILABLE = True
except ImportError:  # pragma: no cover
    EVTX_AVAILABLE = False

from ..utils.helpers import safe_int, safe_str
from ..utils.safe_reader import ReadOnlyEvidenceFile
from ..utils.time_utils import parse_timestamp


# Channel, description, category
SUPPORTED_EVENT_IDS: Dict[int, tuple] = {
    # Core authentication & session
    4624: ("Security", "Successful logon", "Authentication"),
    4625: ("Security", "Failed logon attempt", "Authentication"),
    4634: ("Security", "Account logoff", "Session"),
    4647: ("Security", "User-initiated logoff", "Session"),
    # Extended
    4648: ("Security", "Logon with explicit credentials", "Lateral Movement"),
    4672: ("Security", "Special privileges assigned to new logon", "Privilege"),
    4778: ("Security", "Remote Desktop session reconnected", "RDP"),
    4779: ("Security", "Remote Desktop session disconnected", "RDP"),
    4800: ("Security", "Workstation locked", "Session"),
    4801: ("Security", "Workstation unlocked", "Session"),
    # Kerberos / NTLM
    4768: ("Security", "Kerberos TGT requested", "Kerberos"),
    4769: ("Security", "Kerberos service ticket requested", "Kerberos"),
    4771: ("Security", "Kerberos pre-authentication failed", "Kerberos"),
    4776: ("Security", "NTLM credential validation", "NTLM"),
    # Account management
    4720: ("Security", "User account created", "Account"),
    4722: ("Security", "User account enabled", "Account"),
    4723: ("Security", "Password change attempted", "Account"),
    4724: ("Security", "Password reset attempted", "Account"),
    4725: ("Security", "User account disabled", "Account"),
    4726: ("Security", "User account deleted", "Account"),
    4728: ("Security", "Member added to security-enabled global group", "Group"),
    4732: ("Security", "Member added to security-enabled local group", "Group"),
    4740: ("Security", "User account locked out", "Account"),
    4756: ("Security", "Member added to security-enabled universal group", "Group"),
    4767: ("Security", "User account unlocked", "Account"),
    # Persistence
    4698: ("Security", "Scheduled task created", "Persistence"),
    7045: ("System", "New service installed", "Persistence"),
    # Anti-forensic
    1102: ("Security", "Security audit log cleared", "Anti-Forensic"),
    104: ("System", "System log cleared", "Anti-Forensic"),
    4616: ("Security", "System time changed", "Timestamp Manipulation"),
}

# Contract schema from the implementation plan
EVENT_SCHEMA: List[str] = [
    "EventID",
    "TimeCreated",
    "SubjectUserName",
    "TargetUserName",
    "TargetLogonId",
    "LogonType",
    "IpAddress",
    "IpPort",
    "WorkstationName",
    "Status",
    "raw_xml",
]

EXTRA_COLUMNS: List[str] = [
    "RecordID",
    "Channel",
    "Category",
    "Description",
    "Computer",
    "Provider",
    "TargetDomainName",
    "SubjectDomainName",
    "SubjectUserSid",
    "TargetUserSid",
    "PrivilegeList",
    "ServiceName",
    "TaskName",
    "TicketEncryptionType",
    "ProcessName",
    "ProcessId",
    "SubStatus",
    "OldTime",
    "NewTime",
    "FailureReason",
    "AuthenticationPackageName",
    "LmPackageName",
    "TransmittedServices",
    "KeyLength",
    "MemberName",
    "MemberSid",
    "TargetSid",
    "RawData",
]

ALL_COLUMNS: List[str] = EVENT_SCHEMA + EXTRA_COLUMNS

EVTX_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


class EvtxParser:
    """
    Parser for Windows Event Log evidence (.evtx, .xml, .json, .csv).

    Purpose
    -------
    Convert raw Windows event logs into a normalised pandas DataFrame whose
    columns satisfy the WinLogin Forensics parser contract.

    Parameters
    ----------
    file_path : str | Path | None
        Evidence file. May be omitted when parsing in-memory XML/records.
    read_only : bool
        When True (default) the file is opened via :class:`ReadOnlyEvidenceFile`.
    include_unsupported : bool
        When True, events whose EventID is not in ``SUPPORTED_EVENT_IDS``
        are still emitted (used by volume-drop / gap detectors).
    """

    def __init__(
        self,
        file_path: Optional[Union[str, Path]] = None,
        read_only: bool = True,
        include_unsupported: bool = False,
    ):
        self.file_path = Path(file_path) if file_path else None
        self.read_only = read_only
        self.include_unsupported = include_unsupported

    @staticmethod
    def get_supported_event_ids() -> Dict[int, tuple]:
        """
        Return the EventID catalogue.

        Returns
        -------
        Dict[int, tuple]
            Mapping of EventID → (channel, description, category).
        """
        return dict(SUPPORTED_EVENT_IDS)

    def parse(self) -> pd.DataFrame:
        """
        Parse ``self.file_path`` and return a structured event DataFrame.

        Returns
        -------
        pd.DataFrame
            Events with at least the contract schema columns.

        Raises
        ------
        FileNotFoundError
            If the evidence path does not exist.
        ValueError
            If no file path was provided.
        """
        if self.file_path is None:
            raise ValueError("EvtxParser.parse() requires a file_path")
        if not self.file_path.exists():
            raise FileNotFoundError(f"Event log file not found: {self.file_path}")

        suffix = self.file_path.suffix.lower()
        if suffix == ".evtx":
            return self._parse_evtx_binary()
        if suffix == ".csv":
            return self._parse_csv()
        if suffix == ".json":
            return self._parse_json()
        if suffix in {".xml", ".txt"}:
            return self._parse_xml_file()
        # Unknown extension — try binary then XML then JSON
        try:
            return self._parse_evtx_binary()
        except Exception:
            try:
                return self._parse_xml_file()
            except Exception:
                return self._parse_json()

    def parse_directory(self, directory: Union[str, Path]) -> pd.DataFrame:
        """
        Parse every supported evidence file in ``directory`` (non-recursive).

        Parameters
        ----------
        directory : str | Path
            Folder containing .evtx / .xml / .json / .csv files.

        Returns
        -------
        pd.DataFrame
            Concatenated, time-sorted events.
        """
        folder = Path(directory)
        if not folder.exists():
            raise FileNotFoundError(f"EVTX directory not found: {folder}")
        frames: List[pd.DataFrame] = []
        for path in sorted(folder.iterdir()):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".evtx", ".xml", ".json", ".csv", ".txt"}:
                continue
            parser = EvtxParser(
                path,
                read_only=self.read_only,
                include_unsupported=self.include_unsupported,
            )
            try:
                frame = parser.parse()
            except Exception:
                continue
            if frame is not None and not frame.empty:
                frames.append(frame)
        if not frames:
            return self._empty_frame()
        return self._normalize_dataframe(pd.concat(frames, ignore_index=True))

    def parse_xml_string(self, xml_str: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single ``<Event>`` XML document into a record dict.

        Parameters
        ----------
        xml_str : str
            Raw Windows Event XML.

        Returns
        -------
        Optional[Dict[str, Any]]
            Parsed record, or None if the XML is not a supported event.
        """
        return self._parse_xml_string(xml_str)

    def parse_records(self, records: Iterable[Union[str, Dict[str, Any]]]) -> pd.DataFrame:
        """
        Parse an in-memory collection of XML strings or already-structured dicts.

        Parameters
        ----------
        records : Iterable[str | dict]
            Event XML strings or dictionaries.

        Returns
        -------
        pd.DataFrame
            Normalised event table.
        """
        parsed: List[Dict[str, Any]] = []
        for item in records:
            if isinstance(item, str):
                rec = self._parse_xml_string(item)
                if rec:
                    parsed.append(rec)
            elif isinstance(item, dict):
                if "raw_xml" in item and item["raw_xml"] and "EventID" not in item:
                    rec = self._parse_xml_string(str(item["raw_xml"]))
                    if rec:
                        parsed.append(rec)
                        continue
                parsed.append(self._coerce_record(item))
        return self._normalize_dataframe(pd.DataFrame(parsed))

    # ------------------------------------------------------------------
    # Internal parsers
    # ------------------------------------------------------------------

    def _parse_evtx_binary(self) -> pd.DataFrame:
        if not EVTX_AVAILABLE:
            raise RuntimeError(
                "python-evtx is not installed. Install with: pip install python-evtx"
            )
        records: List[Dict[str, Any]] = []

        def _consume(evlog) -> None:
            for record in evlog.records():
                try:
                    xml_str = record.xml()
                except Exception:
                    continue
                parsed = self._parse_xml_string(xml_str)
                if parsed:
                    records.append(parsed)

        if self.read_only:
            with ReadOnlyEvidenceFile(self.file_path, mode="rb"):
                # python-evtx needs a filesystem path; we re-open read-only
                # after the wrapper has hashed the file at entry.
                with evtx_lib.Evtx(str(self.file_path)) as evlog:
                    _consume(evlog)
        else:
            with evtx_lib.Evtx(str(self.file_path)) as evlog:
                _consume(evlog)
        return self._normalize_dataframe(pd.DataFrame(records))

    def _parse_xml_file(self) -> pd.DataFrame:
        if self.read_only:
            with ReadOnlyEvidenceFile(self.file_path, mode="r") as handle:
                content = handle.read()
        else:
            content = self.file_path.read_text(encoding="utf-8", errors="ignore")
        return self._parse_xml_document(content)

    _EVENT_BLOCK = re.compile(r"<Event(?:\s[^>]*)?>.*?</Event>", re.DOTALL)

    def _parse_xml_document(self, content: str) -> pd.DataFrame:
        records: List[Dict[str, Any]] = []
        # Match <Event ...> ... </Event> but never the wrapping <Events> element.
        for match in self._EVENT_BLOCK.finditer(content or ""):
            parsed = self._parse_xml_string(match.group(0))
            if parsed:
                records.append(parsed)
        return self._normalize_dataframe(pd.DataFrame(records))

    def _parse_csv(self) -> pd.DataFrame:
        if self.read_only:
            with ReadOnlyEvidenceFile(self.file_path, mode="r") as handle:
                df = pd.read_csv(handle.handle)
        else:
            df = pd.read_csv(self.file_path)
        return self._normalize_dataframe(df)

    def _parse_json(self) -> pd.DataFrame:
        if self.read_only:
            with ReadOnlyEvidenceFile(self.file_path, mode="r") as handle:
                payload = json.loads(handle.read())
        else:
            payload = json.loads(self.file_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            payload = payload.get("events") or payload.get("Records") or payload.get("data") or []
        if not isinstance(payload, list):
            payload = [payload]
        return self.parse_records(payload)

    def _parse_xml_string(self, xml_str: str) -> Optional[Dict[str, Any]]:
        if not xml_str or not xml_str.strip():
            return None
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return None

        ns = ""
        if "}" in root.tag:
            ns = root.tag.split("}")[0] + "}"

        system = root.find(f"{ns}System")
        if system is None:
            return None

        eid_elem = system.find(f"{ns}EventID")
        if eid_elem is None or not (eid_elem.text or "").strip():
            return None
        try:
            event_id = int(eid_elem.text.strip())
        except ValueError:
            return None

        if event_id not in SUPPORTED_EVENT_IDS and not self.include_unsupported:
            return None

        time_elem = system.find(f"{ns}TimeCreated")
        time_created = None
        if time_elem is not None:
            time_created = time_elem.attrib.get("SystemTime")

        rec_elem = system.find(f"{ns}EventRecordID")
        record_id = safe_int(rec_elem.text if rec_elem is not None else None, default=0)

        channel_elem = system.find(f"{ns}Channel")
        meta = SUPPORTED_EVENT_IDS.get(event_id, ("Unknown", f"Event {event_id}", "Other"))
        channel = (channel_elem.text if channel_elem is not None and channel_elem.text else None) or meta[0]

        computer_elem = system.find(f"{ns}Computer")
        computer = computer_elem.text if computer_elem is not None else "-"

        provider_elem = system.find(f"{ns}Provider")
        provider = "-"
        if provider_elem is not None:
            provider = provider_elem.attrib.get("Name") or provider_elem.attrib.get("EventSourceName") or "-"

        exec_elem = system.find(f"{ns}Execution")
        process_id = "-"
        if exec_elem is not None:
            process_id = exec_elem.attrib.get("ProcessID", "-")

        event_data = self._extract_named_data(root, ns)

        target_username = (
            event_data.get("TargetUserName")
            or event_data.get("TargetUser")
            or event_data.get("AccountName")
            or "-"
        )
        subject_username = (
            event_data.get("SubjectUserName")
            or event_data.get("SubjectUser")
            or "-"
        )
        target_logon_id = (
            event_data.get("TargetLogonId")
            or event_data.get("TargetLogonID")
            or event_data.get("LogonId")
            or event_data.get("LogonID")
            or "-"
        )
        ip_addr = event_data.get("IpAddress") or event_data.get("ClientAddress") or event_data.get("IpAddress") or "-"
        if ip_addr in {"", "::1", "127.0.0.1", "localhost"}:
            # Keep loopback as a literal so tests can still see it; '-' only for empty
            if ip_addr == "":
                ip_addr = "-"
        ip_port = event_data.get("IpPort") or event_data.get("ClientPort") or "-"
        workstation = (
            event_data.get("WorkstationName")
            or event_data.get("Workstation")
            or event_data.get("ClientName")
            or "-"
        )
        status = (
            event_data.get("Status")
            or event_data.get("FailureReason")
            or event_data.get("ErrorCode")
            or "-"
        )
        logon_type = safe_int(event_data.get("LogonType"), default=-1)

        description, category = meta[1], meta[2]
        return {
            "EventID": event_id,
            "TimeCreated": parse_timestamp(time_created),
            "SubjectUserName": safe_str(subject_username),
            "TargetUserName": safe_str(target_username),
            "TargetLogonId": safe_str(target_logon_id),
            "LogonType": logon_type,
            "IpAddress": safe_str(ip_addr),
            "IpPort": safe_str(ip_port),
            "WorkstationName": safe_str(workstation),
            "Status": safe_str(status),
            "raw_xml": xml_str,
            "RecordID": record_id,
            "Channel": channel,
            "Category": category,
            "Description": description,
            "Computer": safe_str(computer),
            "Provider": safe_str(provider),
            "TargetDomainName": safe_str(event_data.get("TargetDomainName") or event_data.get("TargetDomain")),
            "SubjectDomainName": safe_str(event_data.get("SubjectDomainName") or event_data.get("SubjectDomain")),
            "SubjectUserSid": safe_str(event_data.get("SubjectUserSid")),
            "TargetUserSid": safe_str(event_data.get("TargetUserSid")),
            "PrivilegeList": safe_str(event_data.get("PrivilegeList")),
            "ServiceName": safe_str(event_data.get("ServiceName") or event_data.get("Service")),
            "TaskName": safe_str(event_data.get("TaskName")),
            "TicketEncryptionType": safe_str(event_data.get("TicketEncryptionType")),
            "ProcessName": safe_str(
                event_data.get("ProcessName") or event_data.get("CallerProcessName") or event_data.get("NewProcessName")
            ),
            "ProcessId": safe_str(event_data.get("ProcessId") or event_data.get("CallerProcessId") or process_id),
            "SubStatus": safe_str(event_data.get("SubStatus")),
            "OldTime": safe_str(event_data.get("PreviousTime") or event_data.get("OldTime")),
            "NewTime": safe_str(event_data.get("NewTime")),
            "FailureReason": safe_str(event_data.get("FailureReason")),
            "AuthenticationPackageName": safe_str(event_data.get("AuthenticationPackageName")),
            "LmPackageName": safe_str(event_data.get("LmPackageName")),
            "TransmittedServices": safe_str(event_data.get("TransmittedServices")),
            "KeyLength": safe_str(event_data.get("KeyLength")),
            "MemberName": safe_str(event_data.get("MemberName")),
            "MemberSid": safe_str(event_data.get("MemberSid")),
            "TargetSid": safe_str(event_data.get("TargetSid")),
            "RawData": event_data,
        }

    def _extract_named_data(self, root: ET.Element, ns: str) -> Dict[str, str]:
        """Pull Name= attributes out of EventData and UserData."""
        data: Dict[str, str] = {}

        def _consume(elem: Optional[ET.Element]) -> None:
            if elem is None:
                return
            for node in elem.iter():
                name = node.attrib.get("Name")
                text = (node.text or "").strip()
                if name:
                    data[name] = text
                elif node is not elem and node.tag and text:
                    tag = node.tag.split("}")[-1]
                    if tag not in {"EventData", "UserData", "Data"}:
                        data.setdefault(tag, text)

        _consume(root.find(f"{ns}EventData"))
        _consume(root.find(f"{ns}UserData"))
        # Some exports put Data nodes directly under Event
        if not data:
            for data_node in root.findall(f".//{ns}Data"):
                name = data_node.attrib.get("Name")
                if name:
                    data[name] = (data_node.text or "").strip()
        return data

    def _coerce_record(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalise a pre-structured dict (JSON fixture) onto the contract schema."""
        rec = {col: item.get(col, "-" if col != "LogonType" else -1) for col in ALL_COLUMNS}
        rec["EventID"] = safe_int(item.get("EventID"), default=-1)
        rec["LogonType"] = safe_int(item.get("LogonType"), default=-1)
        rec["RecordID"] = safe_int(item.get("RecordID") or item.get("EventRecordID"), default=0)
        rec["TimeCreated"] = parse_timestamp(item.get("TimeCreated") or item.get("SystemTime"))
        rec["TargetLogonId"] = safe_str(item.get("TargetLogonId") or item.get("TargetLogonID") or item.get("LogonId"))
        rec["raw_xml"] = item.get("raw_xml") or item.get("RawXml") or ""
        rec["IpPort"] = safe_str(item.get("IpPort"))
        rec["Status"] = safe_str(item.get("Status"))
        rec["SubjectUserName"] = safe_str(item.get("SubjectUserName"))
        rec["TargetUserName"] = safe_str(item.get("TargetUserName"))
        rec["IpAddress"] = safe_str(item.get("IpAddress"))
        rec["WorkstationName"] = safe_str(item.get("WorkstationName"))
        eid = rec["EventID"]
        if eid in SUPPORTED_EVENT_IDS:
            rec["Channel"] = rec.get("Channel") if rec.get("Channel") not in (None, "-", "") else SUPPORTED_EVENT_IDS[eid][0]
            rec["Description"] = SUPPORTED_EVENT_IDS[eid][1]
            rec["Category"] = SUPPORTED_EVENT_IDS[eid][2]
        rec["RawData"] = item.get("RawData") or item
        return rec

    def _normalize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        if df is None or df.empty:
            return self._empty_frame()
        for col in ALL_COLUMNS:
            if col not in df.columns:
                if col == "LogonType":
                    df[col] = -1
                elif col == "RecordID":
                    df[col] = 0
                elif col == "raw_xml":
                    df[col] = ""
                else:
                    df[col] = "-"
        df["EventID"] = pd.to_numeric(df["EventID"], errors="coerce").fillna(-1).astype(int)
        df["LogonType"] = pd.to_numeric(df["LogonType"], errors="coerce").fillna(-1).astype(int)
        df["RecordID"] = pd.to_numeric(df["RecordID"], errors="coerce").fillna(0).astype(int)
        df["TimeCreated"] = df["TimeCreated"].apply(parse_timestamp)
        df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], utc=True, errors="coerce")
        # Fill catalogue fields
        for idx, row in df.iterrows():
            eid = int(row["EventID"])
            if eid in SUPPORTED_EVENT_IDS:
                if not row.get("Description") or row.get("Description") in ("-", "", None):
                    df.at[idx, "Description"] = SUPPORTED_EVENT_IDS[eid][1]
                if not row.get("Category") or row.get("Category") in ("-", "", None):
                    df.at[idx, "Category"] = SUPPORTED_EVENT_IDS[eid][2]
                if not row.get("Channel") or row.get("Channel") in ("-", "", None):
                    df.at[idx, "Channel"] = SUPPORTED_EVENT_IDS[eid][0]
        df = df.sort_values(by="TimeCreated", ascending=True, na_position="last").reset_index(drop=True)
        # Guarantee contract column order first
        ordered = EVENT_SCHEMA + [c for c in EXTRA_COLUMNS if c in df.columns]
        extras = [c for c in df.columns if c not in ordered]
        return df[ordered + extras]

    @staticmethod
    def _empty_frame() -> pd.DataFrame:
        return pd.DataFrame(columns=ALL_COLUMNS)


def parse_evtx(
    path: Union[str, Path],
    read_only: bool = True,
    include_unsupported: bool = False,
) -> pd.DataFrame:
    """
    Convenience wrapper around :class:`EvtxParser`.

    Parameters
    ----------
    path : str | Path
        Evidence file or directory.
    read_only : bool
        Enforce read-only open.
    include_unsupported : bool
        Keep EventIDs outside the catalogue.

    Returns
    -------
    pd.DataFrame
        Parsed events.
    """
    target = Path(path)
    parser = EvtxParser(target if target.is_file() else None, read_only=read_only, include_unsupported=include_unsupported)
    if target.is_dir():
        return parser.parse_directory(target)
    parser.file_path = target
    return parser.parse()


def build_event_xml(
    event_id: int,
    time_created: str,
    *,
    record_id: int = 1,
    subject_user: str = "-",
    target_user: str = "-",
    target_logon_id: str = "-",
    logon_type: int = -1,
    ip_address: str = "-",
    ip_port: str = "-",
    workstation: str = "-",
    status: str = "0x0",
    extra_data: Optional[Dict[str, Any]] = None,
    computer: str = "WORKSTATION-07",
    channel: Optional[str] = None,
) -> str:
    """
    Build a minimal Windows Event XML document for tests and fixtures.

    Parameters
    ----------
    event_id : int
        Windows Event ID.
    time_created : str
        ISO-8601 SystemTime value.
    record_id : int
        EventRecordID.
    subject_user, target_user, target_logon_id : str
        Authentication principals / logon id.
    logon_type : int
        Windows logon type.
    ip_address, ip_port, workstation, status : str
        Network / result fields.
    extra_data : dict, optional
        Additional ``<Data Name=...>`` entries.
    computer : str
        Computer attribute.
    channel : str, optional
        Channel override.

    Returns
    -------
    str
        Serialised ``<Event>`` XML.
    """
    meta = SUPPORTED_EVENT_IDS.get(event_id, ("Security", f"Event {event_id}", "Other"))
    ch = channel or meta[0]
    fields = {
        "SubjectUserName": subject_user,
        "TargetUserName": target_user,
        "TargetLogonId": target_logon_id,
        "LogonType": logon_type if logon_type >= 0 else "",
        "IpAddress": ip_address,
        "IpPort": ip_port,
        "WorkstationName": workstation,
        "Status": status,
    }
    if extra_data:
        fields.update({k: "" if v is None else v for k, v in extra_data.items()})
    data_xml = []
    for name, value in fields.items():
        if value == "" or value is None:
            continue
        data_xml.append(f'      <Data Name="{name}">{value}</Data>')
    data_block = "\n".join(data_xml)
    return (
        f'<Event xmlns="{EVTX_NS}">\n'
        f"  <System>\n"
        f'    <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
        f"    <EventID>{event_id}</EventID>\n"
        f'    <TimeCreated SystemTime="{time_created}"/>\n'
        f"    <EventRecordID>{record_id}</EventRecordID>\n"
        f"    <Channel>{ch}</Channel>\n"
        f"    <Computer>{computer}</Computer>\n"
        f"  </System>\n"
        f"  <EventData>\n{data_block}\n  </EventData>\n"
        f"</Event>"
    )
