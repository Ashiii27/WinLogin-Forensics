"""
WinLogin Forensics - Sysmon Parser
==================================
Parses Microsoft-Windows-Sysmon/Operational events (EIDs 1, 3, 11, 22)
to recover process creation, network connections, file creation, and DNS
queries for later session correlation.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd

from ..utils.helpers import safe_str
from ..utils.safe_reader import ReadOnlyEvidenceFile
from ..utils.time_utils import parse_timestamp

try:
    import Evtx.Evtx as evtx_lib

    EVTX_AVAILABLE = True
except ImportError:  # pragma: no cover
    EVTX_AVAILABLE = False


SYSMON_EVENT_IDS = {
    1: "Process creation",
    3: "Network connection",
    11: "File created",
    22: "DNS query",
}

SYSMON_COLUMNS = [
    "EventID",
    "UtcTime",
    "TimeCreated",
    "ProcessId",
    "ParentProcessId",
    "CommandLine",
    "User",
    "Hashes",
    "Image",
    "ParentImage",
    "DestinationIp",
    "DestinationPort",
    "Protocol",
    "TargetFilename",
    "CreationUtcTime",
    "QueryName",
    "QueryResults",
    "Description",
    "raw_xml",
]


class SysmonParser:
    """
    Parser for Sysmon Operational logs (.evtx, .xml, .json, .csv).

    Parameters
    ----------
    file_path : str | Path, optional
        Evidence path.
    read_only : bool
        Open evidence read-only.
    """

    def __init__(self, file_path: Optional[Union[str, Path]] = None, read_only: bool = True):
        self.file_path = Path(file_path) if file_path else None
        self.read_only = read_only

    def parse(self, file_path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
        """
        Parse Sysmon evidence into a standardised DataFrame.

        Parameters
        ----------
        file_path : str | Path, optional
            Override path.

        Returns
        -------
        pd.DataFrame
            Sysmon events with EID 1/3/11/22 fields.
        """
        path = Path(file_path) if file_path else self.file_path
        if path is None or not path.exists():
            return self._empty()
        suffix = path.suffix.lower()
        if suffix == ".json":
            payload = self._read_json(path)
            return self.parse_records(payload)
        if suffix == ".csv":
            df = pd.read_csv(path)
            return self._normalize(df)
        if suffix in {".xml", ".txt"}:
            content = self._read_text(path)
            return self._parse_xml_document(content)
        if suffix == ".evtx" and EVTX_AVAILABLE:
            return self._parse_evtx(path)
        return self._empty()

    def parse_records(self, records: List[Any]) -> pd.DataFrame:
        """
        Parse a list of XML strings or dicts.

        Parameters
        ----------
        records : list
            Raw events.

        Returns
        -------
        pd.DataFrame
            Normalised Sysmon table.
        """
        if isinstance(records, dict):
            records = records.get("events") or records.get("Records") or records.get("data") or []
        rows: List[Dict[str, Any]] = []
        for item in records or []:
            if isinstance(item, str):
                rec = self._parse_xml_string(item)
                if rec:
                    rows.append(rec)
            elif isinstance(item, dict):
                rows.append(self._coerce(item))
        return self._normalize(pd.DataFrame(rows))

    def _parse_evtx(self, path: Path) -> pd.DataFrame:
        rows: List[Dict[str, Any]] = []
        with ReadOnlyEvidenceFile(path, mode="rb"):
            with evtx_lib.Evtx(str(path)) as evlog:
                for record in evlog.records():
                    try:
                        rec = self._parse_xml_string(record.xml())
                    except Exception:
                        continue
                    if rec:
                        rows.append(rec)
        return self._normalize(pd.DataFrame(rows))

    def _parse_xml_document(self, content: str) -> pd.DataFrame:
        import re

        blocks = re.findall(r"<Event(?:\s[^>]*)?>.*?</Event>", content or "", flags=re.DOTALL)
        rows = []
        for block in blocks:
            rec = self._parse_xml_string(block)
            if rec:
                rows.append(rec)
        return self._normalize(pd.DataFrame(rows))

    def _parse_xml_string(self, xml_str: str) -> Optional[Dict[str, Any]]:
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return None
        ns = root.tag.split("}")[0] + "}" if "}" in root.tag else ""
        system = root.find(f"{ns}System")
        if system is None:
            return None
        eid_elem = system.find(f"{ns}EventID")
        if eid_elem is None or not eid_elem.text:
            return None
        try:
            event_id = int(eid_elem.text.strip())
        except ValueError:
            return None
        if event_id not in SYSMON_EVENT_IDS:
            return None
        time_elem = system.find(f"{ns}TimeCreated")
        time_created = time_elem.attrib.get("SystemTime") if time_elem is not None else None
        data: Dict[str, str] = {}
        event_data = root.find(f"{ns}EventData")
        if event_data is not None:
            for node in event_data.findall(f"{ns}Data"):
                name = node.attrib.get("Name")
                if name:
                    data[name] = (node.text or "").strip()
        utc = data.get("UtcTime") or time_created
        return {
            "EventID": event_id,
            "UtcTime": parse_timestamp(utc),
            "TimeCreated": parse_timestamp(time_created or utc),
            "ProcessId": safe_str(data.get("ProcessId") or data.get("ProcessID")),
            "ParentProcessId": safe_str(data.get("ParentProcessId") or data.get("ParentProcessID")),
            "CommandLine": safe_str(data.get("CommandLine")),
            "User": safe_str(data.get("User") or data.get("UserName")),
            "Hashes": safe_str(data.get("Hashes") or data.get("Hash")),
            "Image": safe_str(data.get("Image")),
            "ParentImage": safe_str(data.get("ParentImage")),
            "DestinationIp": safe_str(data.get("DestinationIp") or data.get("DestinationIp")),
            "DestinationPort": safe_str(data.get("DestinationPort")),
            "Protocol": safe_str(data.get("Protocol")),
            "TargetFilename": safe_str(data.get("TargetFilename")),
            "CreationUtcTime": parse_timestamp(data.get("CreationUtcTime")),
            "QueryName": safe_str(data.get("QueryName")),
            "QueryResults": safe_str(data.get("QueryResults")),
            "Description": SYSMON_EVENT_IDS[event_id],
            "raw_xml": xml_str,
        }

    def _coerce(self, item: Dict[str, Any]) -> Dict[str, Any]:
        utc = parse_timestamp(item.get("UtcTime") or item.get("TimeCreated"))
        return {
            "EventID": int(item.get("EventID", 0) or 0),
            "UtcTime": utc,
            "TimeCreated": parse_timestamp(item.get("TimeCreated")) or utc,
            "ProcessId": safe_str(item.get("ProcessId")),
            "ParentProcessId": safe_str(item.get("ParentProcessId")),
            "CommandLine": safe_str(item.get("CommandLine")),
            "User": safe_str(item.get("User")),
            "Hashes": safe_str(item.get("Hashes")),
            "Image": safe_str(item.get("Image")),
            "ParentImage": safe_str(item.get("ParentImage")),
            "DestinationIp": safe_str(item.get("DestinationIp")),
            "DestinationPort": safe_str(item.get("DestinationPort")),
            "Protocol": safe_str(item.get("Protocol")),
            "TargetFilename": safe_str(item.get("TargetFilename")),
            "CreationUtcTime": parse_timestamp(item.get("CreationUtcTime")),
            "QueryName": safe_str(item.get("QueryName")),
            "QueryResults": safe_str(item.get("QueryResults")),
            "Description": SYSMON_EVENT_IDS.get(int(item.get("EventID", 0) or 0), "Sysmon"),
            "raw_xml": item.get("raw_xml", ""),
        }

    def _normalize(self, df: pd.DataFrame) -> pd.DataFrame:
        if df is None or df.empty:
            return self._empty()
        for col in SYSMON_COLUMNS:
            if col not in df.columns:
                df[col] = pd.NaT if col in {"UtcTime", "TimeCreated", "CreationUtcTime"} else "-"
        df["EventID"] = pd.to_numeric(df["EventID"], errors="coerce").fillna(0).astype(int)
        df["UtcTime"] = pd.to_datetime(df["UtcTime"], utc=True, errors="coerce")
        df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], utc=True, errors="coerce")
        df = df.sort_values("UtcTime", na_position="last").reset_index(drop=True)
        return df[SYSMON_COLUMNS]

    def _read_json(self, path: Path):
        if self.read_only:
            with ReadOnlyEvidenceFile(path, mode="r") as handle:
                return json.loads(handle.read())
        return json.loads(path.read_text(encoding="utf-8"))

    def _read_text(self, path: Path) -> str:
        if self.read_only:
            with ReadOnlyEvidenceFile(path, mode="r") as handle:
                return handle.read()
        return path.read_text(encoding="utf-8", errors="ignore")

    @staticmethod
    def _empty() -> pd.DataFrame:
        return pd.DataFrame(columns=SYSMON_COLUMNS)
