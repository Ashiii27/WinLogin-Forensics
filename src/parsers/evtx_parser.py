"""
WinLogin Forensics - EVTX Parser
=====================================================
Parses Windows Security and System Event Log (.evtx) files,
extracting 35+ authentication, session, Kerberos, account management,
persistence, and anti-forensic Event IDs into structured pandas DataFrames.
"""

import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import pandas as pd

try:
    import Evtx.Evtx as evtx_lib
    import Evtx.Views as evtx_views
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

from ..utils.time_utils import parse_timestamp, normalize_to_utc
from ..utils.safe_reader import ReadOnlyEvidenceFile


SUPPORTED_EVENT_IDS = {
    # Authentication & Session
    4624: ("Security", "Successful logon", "Authentication"),
    4625: ("Security", "Failed logon attempt", "Authentication"),
    4634: ("Security", "Account logoff", "Session"),
    4647: ("Security", "User-initiated logoff", "Session"),
    4648: ("Security", "Logon with explicit credentials", "Lateral Movement"),
    4672: ("Security", "Special privileges assigned to new logon", "Privilege"),
    4778: ("Security", "Remote Desktop session reconnected", "RDP"),
    4779: ("Security", "Remote Desktop session disconnected", "RDP"),
    4800: ("Security", "Workstation locked", "Session"),
    4801: ("Security", "Workstation unlocked", "Session"),
    # Kerberos Events
    4768: ("Security", "Kerberos TGT requested", "Kerberos"),
    4769: ("Security", "Kerberos service ticket requested", "Kerberos"),
    4771: ("Security", "Kerberos pre-authentication failed", "Kerberos"),
    4776: ("Security", "NTLM credential validation", "NTLM"),
    # Account Management
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
    # Privilege & Persistence
    4698: ("Security", "Scheduled task created", "Persistence"),
    7045: ("System", "New service installed", "Persistence"),
    # Anti-Forensic Events
    1102: ("Security", "Security audit log cleared", "Anti-Forensic"),
    104: ("System", "System log cleared", "Anti-Forensic"),
    4616: ("Security", "System time changed", "Timestamp Manipulation"),
}


class EvtxParser:
    """
    Parser for Windows Event Log (.evtx, .xml, .csv, .json) evidence files.
    """
    def __init__(self, file_path: Union[str, Path], read_only: bool = True):
        self.file_path = Path(file_path)
        self.read_only = read_only

    @staticmethod
    def get_supported_event_ids() -> Dict[int, tuple]:
        return SUPPORTED_EVENT_IDS

    def parse(self) -> pd.DataFrame:
        """
        Parse the input file and return a pandas DataFrame of parsed event records.
        """
        if not self.file_path.exists():
            raise FileNotFoundError(f"Event log file not found: {self.file_path}")

        suffix = self.file_path.suffix.lower()
        if suffix == ".evtx":
            return self._parse_evtx_binary()
        elif suffix == ".csv":
            return self._parse_csv()
        elif suffix == ".json":
            return self._parse_json()
        elif suffix == ".xml":
            return self._parse_xml()
        else:
            # Fallback attempt binary evtx or CSV
            try:
                return self._parse_evtx_binary()
            except Exception:
                return self._parse_csv()

    def _parse_evtx_binary(self) -> pd.DataFrame:
        if not EVTX_AVAILABLE:
            raise RuntimeError("python-evtx library is not available in environment.")

        records = []
        # Enforce read-only wrapper if requested
        if self.read_only:
            with ReadOnlyEvidenceFile(self.file_path, mode="rb") as ro_file:
                with evtx_lib.Evtx(ro_file.file_path) as evlog:
                    for record in evlog.records():
                        try:
                            xml_str = record.xml()
                            parsed_rec = self._parse_xml_string(xml_str)
                            if parsed_rec:
                                records.append(parsed_rec)
                        except Exception:
                            continue
        else:
            with evtx_lib.Evtx(str(self.file_path)) as evlog:
                for record in evlog.records():
                    try:
                        xml_str = record.xml()
                        parsed_rec = self._parse_xml_string(xml_str)
                        if parsed_rec:
                            records.append(parsed_rec)
                    except Exception:
                        continue

        df = pd.DataFrame(records)
        return self._normalize_dataframe(df)

    def _parse_xml(self) -> pd.DataFrame:
        with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        records = []
        # Support root <Events> or multiple <Event> tags
        if "<Event " in content or "<Event>" in content:
            # Simple splitter for XML events
            parts = content.split("<Event")
            for part in parts[1:]:
                xml_str = "<Event" + part
                if "</Event>" in xml_str:
                    xml_str = xml_str.split("</Event>")[0] + "</Event>"
                    parsed = self._parse_xml_string(xml_str)
                    if parsed:
                        records.append(parsed)
        df = pd.DataFrame(records)
        return self._normalize_dataframe(df)

    def _parse_csv(self) -> pd.DataFrame:
        df = pd.read_csv(self.file_path)
        return self._normalize_dataframe(df)

    def _parse_json(self) -> pd.DataFrame:
        df = pd.read_json(self.file_path)
        return self._normalize_dataframe(df)

    def _parse_xml_string(self, xml_str: str) -> Optional[Dict[str, Any]]:
        try:
            root = ET.fromstring(xml_str)
        except Exception:
            return None

        # Strip namespace if present
        ns = ""
        if "}" in root.tag:
            ns = root.tag.split("}")[0] + "}"

        system = root.find(f"{ns}System")
        if system is None:
            return None

        # Extract EventID
        eid_elem = system.find(f"{ns}EventID")
        if eid_elem is None or not eid_elem.text:
            return None
        try:
            event_id = int(eid_elem.text)
        except ValueError:
            return None

        # Check if we care about this EventID
        if event_id not in SUPPORTED_EVENT_IDS:
            return None

        # Extract TimeCreated
        time_elem = system.find(f"{ns}TimeCreated")
        time_created = time_elem.attrib.get("SystemTime") if time_elem is not None else None

        # Extract RecordID
        rec_elem = system.find(f"{ns}EventRecordID")
        record_id = int(rec_elem.text) if rec_elem is not None and rec_elem.text else 0

        # Extract Channel
        channel_elem = system.find(f"{ns}Channel")
        channel = channel_elem.text if channel_elem is not None else SUPPORTED_EVENT_IDS[event_id][0]

        # Extract EventData
        event_data = {}
        event_data_elem = root.find(f"{ns}EventData")
        if event_data_elem is not None:
            for data in event_data_elem.findall(f"{ns}Data"):
                name = data.attrib.get("Name")
                val = data.text or ""
                if name:
                    event_data[name] = val
                else:
                    # Unnamed Data fields indexed by position
                    event_data[f"Data_{len(event_data)}"] = val

        # Extract structured fields
        target_username = event_data.get("TargetUserName") or event_data.get("TargetUser") or event_data.get("SubjectUserName", "-")
        target_domain = event_data.get("TargetDomainName") or event_data.get("SubjectDomainName", "-")
        subject_username = event_data.get("SubjectUserName", "-")
        ip_addr = event_data.get("IpAddress") or event_data.get("ClientAddress") or "-"
        if ip_addr in ("-", "::1", "127.0.0.1", ""):
            ip_addr = "-"

        workstation = event_data.get("WorkstationName") or event_data.get("Workstation") or "-"
        logon_type_val = event_data.get("LogonType")
        try:
            logon_type = int(logon_type_val) if logon_type_val is not None else -1
        except (ValueError, TypeError):
            logon_type = -1

        logon_guid = event_data.get("LogonGuid", "-")
        process_name = event_data.get("ProcessName") or event_data.get("CallerProcessName") or "-"
        status = event_data.get("Status") or event_data.get("FailureReason") or "-"
        sub_status = event_data.get("SubStatus", "-")
        privilege_list = event_data.get("PrivilegeList", "-")
        service_name = event_data.get("ServiceName", "-")
        task_name = event_data.get("TaskName", "-")
        ticket_enc_type = event_data.get("TicketEncryptionType", "-")

        description, category = SUPPORTED_EVENT_IDS[event_id][1], SUPPORTED_EVENT_IDS[event_id][2]

        return {
            "TimeCreated": parse_timestamp(time_created),
            "EventID": event_id,
            "RecordID": record_id,
            "Channel": channel,
            "Category": category,
            "Description": description,
            "TargetUserName": target_username,
            "TargetDomainName": target_domain,
            "SubjectUserName": subject_username,
            "IpAddress": ip_addr,
            "WorkstationName": workstation,
            "LogonType": logon_type,
            "LogonGuid": logon_guid,
            "ProcessName": process_name,
            "Status": status,
            "SubStatus": sub_status,
            "PrivilegeList": privilege_list,
            "ServiceName": service_name,
            "TaskName": task_name,
            "TicketEncryptionType": ticket_enc_type,
            "RawData": event_data,
        }

    def _normalize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame(columns=[
                "TimeCreated", "EventID", "RecordID", "Channel", "Category", "Description",
                "TargetUserName", "TargetDomainName", "SubjectUserName", "IpAddress",
                "WorkstationName", "LogonType", "LogonGuid", "ProcessName", "Status",
                "SubStatus", "PrivilegeList", "ServiceName", "TaskName",
                "TicketEncryptionType", "RawData"
            ])

        # Ensure required columns exist
        required = [
            "TimeCreated", "EventID", "RecordID", "Channel", "Category", "Description",
            "TargetUserName", "TargetDomainName", "SubjectUserName", "IpAddress",
            "WorkstationName", "LogonType", "LogonGuid", "ProcessName", "Status",
            "SubStatus", "PrivilegeList", "ServiceName", "TaskName",
            "TicketEncryptionType", "RawData"
        ]
        for col in required:
            if col not in df.columns:
                df[col] = "-"

        # Fill descriptions and categories if missing
        df["EventID"] = pd.to_numeric(df["EventID"], errors="coerce").fillna(-1).astype(int)
        for idx, row in df.iterrows():
            eid = row["EventID"]
            if eid in SUPPORTED_EVENT_IDS:
                df.at[idx, "Channel"] = SUPPORTED_EVENT_IDS[eid][0]
                df.at[idx, "Description"] = SUPPORTED_EVENT_IDS[eid][1]
                df.at[idx, "Category"] = SUPPORTED_EVENT_IDS[eid][2]
            if not isinstance(row["TimeCreated"], pd.Timestamp):
                df.at[idx, "TimeCreated"] = parse_timestamp(row["TimeCreated"])

        df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], utc=True)
        df = df.sort_values(by="TimeCreated", ascending=True).reset_index(drop=True)
        return df
