"""
WinLogin Forensics - PowerShell Operational Parser
==================================================
Parses Microsoft-Windows-PowerShell/Operational events:

* EID 4103 — Module Logging (module name, pipeline)
* EID 4104 — Script Block Logging (full text + obfuscation markers)
"""

from __future__ import annotations

import json
import re
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


POWERSHELL_EVENT_IDS = {4103: "Module Logging", 4104: "Script Block Logging"}

SUSPICIOUS_KEYWORDS = (
    "iex",
    "invoke-expression",
    "downloadstring",
    "frombase64string",
    "encodedcommand",
    "-enc",
    "[char]",
    "base64",
)

OBFUSCATION_MARKERS = (
    "base64",
    "frombase64string",
    "invoke-expression",
    "iex",
    "[char]",
    "-enc",
    "-encodedcommand",
    "encodedcommand",
)

PS_COLUMNS = [
    "EventID",
    "TimeCreated",
    "User",
    "ModuleName",
    "Pipeline",
    "ScriptBlockText",
    "ScriptBlockId",
    "Path",
    "Suspicious",
    "ObfuscationMarkers",
    "MatchedKeywords",
    "RiskLevel",
    "raw_xml",
]


class PowerShellParser:
    """
    Parser for PowerShell Operational logs (.evtx, .xml, .json, .csv).

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
        Parse PowerShell operational events and tag obfuscation.

        Parameters
        ----------
        file_path : str | Path, optional
            Override path.

        Returns
        -------
        pd.DataFrame
            Script-block / module-logging table.
        """
        path = Path(file_path) if file_path else self.file_path
        if path is None or not path.exists():
            return self._empty()
        suffix = path.suffix.lower()
        if suffix == ".json":
            return self.parse_records(self._read_json(path))
        if suffix == ".csv":
            return self._normalize(pd.read_csv(path))
        if suffix in {".xml", ".txt"}:
            return self._parse_xml_document(self._read_text(path))
        if suffix == ".evtx" and EVTX_AVAILABLE:
            return self._parse_evtx(path)
        return self._empty()

    def parse_records(self, records: Any) -> pd.DataFrame:
        """
        Parse a list of XML strings or dicts.

        Parameters
        ----------
        records : list | dict
            Raw events.

        Returns
        -------
        pd.DataFrame
            Normalised PowerShell table.
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

    @staticmethod
    def flag_obfuscation(text: str) -> List[str]:
        """
        Return obfuscation markers present in ``text``.

        Parameters
        ----------
        text : str
            Script-block body.

        Returns
        -------
        List[str]
            Matched markers (lowercase).
        """
        blob = (text or "").lower()
        hits = [m for m in OBFUSCATION_MARKERS if m in blob]
        # also catch -enc as a token
        if re.search(r"(?i)(^|\s)-enc(odedcommand)?(\s|$)", text or ""):
            if "-enc" not in hits:
                hits.append("-enc")
        return hits

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
        if event_id not in POWERSHELL_EVENT_IDS:
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
        script = data.get("ScriptBlockText") or data.get("Payload") or ""
        pipeline = data.get("ContextInfo") or data.get("Payload") or data.get("MessageNumber") or ""
        module = data.get("FullyQualifiedErrorId") or data.get("ModuleName") or ""
        # 4103 often stores the command in Payload / ContextInfo
        if event_id == 4103 and not module:
            module = data.get("ContextInfo") or "-"
        user = data.get("UserId") or data.get("User") or "-"
        markers = self.flag_obfuscation(script + " " + str(pipeline))
        return {
            "EventID": event_id,
            "TimeCreated": parse_timestamp(time_created),
            "User": safe_str(user),
            "ModuleName": safe_str(module),
            "Pipeline": safe_str(pipeline),
            "ScriptBlockText": script or "-",
            "ScriptBlockId": safe_str(data.get("ScriptBlockId")),
            "Path": safe_str(data.get("Path")),
            "Suspicious": bool(markers),
            "ObfuscationMarkers": ",".join(markers) if markers else "-",
            "MatchedKeywords": ",".join(markers) if markers else "-",
            "RiskLevel": "High" if markers else "Low",
            "raw_xml": xml_str,
        }

    def _coerce(self, item: Dict[str, Any]) -> Dict[str, Any]:
        script = str(item.get("ScriptBlockText") or item.get("Payload") or "")
        pipeline = str(item.get("Pipeline") or item.get("ContextInfo") or "")
        markers = self.flag_obfuscation(script + " " + pipeline)
        return {
            "EventID": int(item.get("EventID", 4104) or 4104),
            "TimeCreated": parse_timestamp(item.get("TimeCreated")),
            "User": safe_str(item.get("User")),
            "ModuleName": safe_str(item.get("ModuleName")),
            "Pipeline": safe_str(pipeline),
            "ScriptBlockText": script or "-",
            "ScriptBlockId": safe_str(item.get("ScriptBlockId")),
            "Path": safe_str(item.get("Path")),
            "Suspicious": bool(markers) if "Suspicious" not in item else bool(item.get("Suspicious")),
            "ObfuscationMarkers": ",".join(markers) if markers else "-",
            "MatchedKeywords": ",".join(markers) if markers else item.get("MatchedKeywords", "-"),
            "RiskLevel": "High" if markers else "Low",
            "raw_xml": item.get("raw_xml", ""),
        }

    def _normalize(self, df: pd.DataFrame) -> pd.DataFrame:
        if df is None or df.empty:
            return self._empty()
        for col in PS_COLUMNS:
            if col not in df.columns:
                df[col] = False if col == "Suspicious" else "-"
        if "ScriptBlockText" in df.columns:
            for idx, row in df.iterrows():
                markers = self.flag_obfuscation(str(row.get("ScriptBlockText", "")))
                if markers:
                    df.at[idx, "Suspicious"] = True
                    df.at[idx, "ObfuscationMarkers"] = ",".join(markers)
                    df.at[idx, "MatchedKeywords"] = ",".join(markers)
                    df.at[idx, "RiskLevel"] = "High"
        df["EventID"] = pd.to_numeric(df["EventID"], errors="coerce").fillna(4104).astype(int)
        df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], utc=True, errors="coerce")
        df = df.sort_values("TimeCreated", na_position="last").reset_index(drop=True)
        return df[PS_COLUMNS]

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
        return pd.DataFrame(columns=PS_COLUMNS)
