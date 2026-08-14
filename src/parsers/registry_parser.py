"""
WinLogin Forensics - Registry Parser
====================================
Extracts forensic artifacts from offline Windows registry hives:

* SAM — RID, username, creation time, last logon, password last set,
  login count, account flags
* SOFTWARE — Run / RunOnce persistence and known remote-access tools
* NTUSER.DAT — UserAssist (ROT13-decoded path, run count, last run)
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd

from ..utils.helpers import rot13_decode, safe_str
from ..utils.safe_reader import ReadOnlyEvidenceFile
from ..utils.time_utils import filetime_to_datetime, parse_timestamp

try:
    from regipy.registry import RegistryHive

    REGIPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    REGIPY_AVAILABLE = False


REMOTE_ACCESS_TOOLS: Dict[str, List[str]] = {
    "TeamViewer": ["teamviewer", "teamviewer.exe", "teamviewer gmbh"],
    "AnyDesk": ["anydesk", "anydesk.exe", "anydesk software"],
    "RDP Wrapper": ["rdpwrap", "rdp wrapper", "termsrv", "fdenytsconnections"],
    "ScreenConnect": ["screenconnect", "connectwise"],
    "RustDesk": ["rustdesk"],
    "AmmyyAdmin": ["ammyy"],
    "Chrome Remote Desktop": ["chrome remote desktop", "remoting_host"],
}

# Win7+ UserAssist value: run count at +4, FILETIME at +60
_USERASSIST_RUNCOUNT_OFF = 4
_USERASSIST_FILETIME_OFF = 60

# SAM F-value layout (NT6+)
_SAM_F_LAST_LOGON = 8
_SAM_F_PASSWORD_SET = 24
_SAM_F_RID = 0x30  # some docs say 0x40; we try both
_SAM_F_RID_ALT = 0x40
_SAM_F_ACB = 0x38
_SAM_F_ACB_ALT = 0x44
_SAM_F_LOGON_COUNT = 0x42  # USHORT at 0x42 in some layouts; also 0x5A
_SAM_F_LOGON_COUNT_ALT = 0x5A

ACB_FLAGS = {
    0x0001: "SCRIPT",
    0x0002: "ACCOUNTDISABLE",
    0x0008: "HOMEDIR_REQUIRED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0040: "PASSWD_CANT_CHANGE",
    0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0100: "TEMP_DUPLICATE_ACCOUNT",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x400000: "USE_DES_KEY_ONLY",
    0x800000: "DONT_REQ_PREAUTH",
    0x1000000: "PASSWORD_EXPIRED",
    0x2000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
}


class RegistryParser:
    """
    Parser for SAM / SOFTWARE / SYSTEM / NTUSER.DAT hives and JSON exports.

    Parameters
    ----------
    hive_path : str | Path, optional
        Path to a hive file or a JSON fixture.
    read_only : bool
        Open evidence read-only (default True).
    """

    def __init__(self, hive_path: Optional[Union[str, Path]] = None, read_only: bool = True):
        self.hive_path = Path(hive_path) if hive_path else None
        self.read_only = read_only

    # ------------------------------------------------------------------
    # SAM
    # ------------------------------------------------------------------

    def parse_sam(self, hive_path: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
        """
        Extract SAM account metadata.

        Parameters
        ----------
        hive_path : str | Path, optional
            Override of ``self.hive_path``.

        Returns
        -------
        List[dict]
            Rows with RID, username, account creation time, last logon,
            password last set, login count, and account flags.
        """
        path = Path(hive_path) if hive_path else self.hive_path
        if path is None or not path.exists():
            return []
        if path.suffix.lower() == ".json":
            return self._load_json_list(path)

        if not REGIPY_AVAILABLE:
            return []

        records: List[Dict[str, Any]] = []
        try:
            hive = self._open_hive(path)
            names = self._get_key(hive, r"SAM\Domains\Account\Users\Names")
            users_root = self._get_key(hive, r"SAM\Domains\Account\Users")
            if names is None:
                return records
            for name_key in names.iter_subkeys():
                username = name_key.name
                rid = self._rid_from_names_key(name_key)
                creation = self._key_mtime(name_key)
                f_bytes = b""
                flags = 0
                last_logon = None
                pwd_set = None
                login_count = 0
                if users_root is not None and rid is not None:
                    rid_key = self._get_key(hive, rf"SAM\Domains\Account\Users\{rid:08X}")
                    if rid_key is None:
                        rid_key = self._get_key(hive, rf"SAM\Domains\Account\Users\{rid:08x}")
                    if rid_key is not None:
                        creation = creation or self._key_mtime(rid_key)
                        f_bytes = self._value_bytes(rid_key, "F")
                        parsed = self._parse_sam_f(f_bytes, fallback_rid=rid)
                        last_logon = parsed["last_logon"]
                        pwd_set = parsed["password_last_set"]
                        login_count = parsed["login_count"]
                        flags = parsed["flags"]
                        if parsed["rid"]:
                            rid = parsed["rid"]
                records.append(
                    {
                        "RID": int(rid or 0),
                        "Username": username,
                        "CreationTime": creation,
                        "LastLogon": last_logon,
                        "PasswordLastSet": pwd_set,
                        "LoginCount": int(login_count or 0),
                        "AccountFlags": flags,
                        "AccountFlagsDecoded": decode_acb(flags),
                        "Enabled": not bool(flags & 0x0002),
                    }
                )
        except Exception:
            return records
        return records

    # ------------------------------------------------------------------
    # SOFTWARE Run keys + RA tools
    # ------------------------------------------------------------------

    def parse_run_keys(self, hive_path: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
        """
        Parse Run / RunOnce persistence values from a SOFTWARE or NTUSER hive.

        Parameters
        ----------
        hive_path : str | Path, optional
            Override path.

        Returns
        -------
        List[dict]
            ``KeyPath, ValueName, Command, Suspicious``.
        """
        path = Path(hive_path) if hive_path else self.hive_path
        if path is None or not path.exists():
            return []
        if path.suffix.lower() == ".json":
            return self._load_json_list(path)
        if not REGIPY_AVAILABLE:
            return []

        candidates = [
            r"Microsoft\Windows\CurrentVersion\Run",
            r"Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
        keys: List[Dict[str, Any]] = []
        try:
            hive = self._open_hive(path)
            seen = set()
            for run_path in candidates:
                key = self._get_key(hive, run_path)
                if key is None:
                    continue
                for val in key.iter_values():
                    sig = (run_path, val.name)
                    if sig in seen:
                        continue
                    seen.add(sig)
                    cmd = "" if val.value is None else str(val.value)
                    keys.append(
                        {
                            "KeyPath": run_path,
                            "ValueName": val.name,
                            "Command": cmd,
                            "Suspicious": _is_suspicious_command(cmd),
                        }
                    )
        except Exception:
            return keys
        return keys

    def parse_remote_access_tools(self, hive_path: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
        """
        Detect remote-access software persistence by known key/value strings.

        Parameters
        ----------
        hive_path : str | Path, optional
            SOFTWARE hive or JSON fixture.

        Returns
        -------
        List[dict]
            One row per matched tool.
        """
        path = Path(hive_path) if hive_path else self.hive_path
        if path is None or not path.exists():
            return []
        if path.suffix.lower() == ".json":
            payload = self._load_json_list(path)
            if payload and "ToolName" in payload[0]:
                return payload

        haystack_parts: List[str] = []
        for item in self.parse_run_keys(path):
            haystack_parts.append(str(item.get("ValueName", "")))
            haystack_parts.append(str(item.get("Command", "")))
            haystack_parts.append(str(item.get("KeyPath", "")))

        if REGIPY_AVAILABLE and path.suffix.lower() != ".json":
            try:
                hive = self._open_hive(path)
                for hint in (
                    r"SOFTWARE\TeamViewer",
                    r"SOFTWARE\AnyDesk",
                    r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                    r"Microsoft\Windows NT\CurrentVersion\Terminal Server",
                    r"Microsoft\TeamViewer",
                    r"AnyDesk",
                ):
                    key = self._get_key(hive, hint)
                    if key is not None:
                        haystack_parts.append(hint)
                        haystack_parts.append(key.name)
                        for val in key.iter_values():
                            haystack_parts.append(str(val.name))
                            haystack_parts.append(str(val.value))
            except Exception:
                pass

        blob = " ".join(haystack_parts).lower()
        hits: List[Dict[str, Any]] = []
        for tool, needles in REMOTE_ACCESS_TOOLS.items():
            if any(n.lower() in blob for n in needles):
                hits.append(
                    {
                        "ToolName": tool,
                        "Category": "Remote Access Tool",
                        "Evidence": f"Matched known artifact tokens: {', '.join(needles[:3])}",
                        "Status": "Detected",
                        "RiskLevel": "High" if tool != "RDP Wrapper" else "Medium",
                    }
                )
        return hits

    # ------------------------------------------------------------------
    # NTUSER.DAT / UserAssist
    # ------------------------------------------------------------------

    def parse_userassist(self, hive_path: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
        """
        Decode UserAssist entries (ROT13 names, run count, last-run FILETIME).

        Parameters
        ----------
        hive_path : str | Path, optional
            NTUSER.DAT or JSON fixture.

        Returns
        -------
        List[dict]
            Decoded UserAssist rows.
        """
        path = Path(hive_path) if hive_path else self.hive_path
        if path is None or not path.exists():
            return []
        if path.suffix.lower() == ".json":
            rows = self._load_json_list(path)
            for row in rows:
                encoded = row.get("EncodedPath") or row.get("Name") or ""
                if encoded and not row.get("DecodedPath"):
                    row["DecodedPath"] = rot13_decode(encoded)
                if "LastExecuted" in row:
                    row["LastExecuted"] = parse_timestamp(row["LastExecuted"])
                if "LastRun" in row and "LastExecuted" not in row:
                    row["LastExecuted"] = parse_timestamp(row["LastRun"])
            return rows
        if not REGIPY_AVAILABLE:
            return []

        results: List[Dict[str, Any]] = []
        ua_roots = [
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        ]
        try:
            hive = self._open_hive(path)
            for root_path in ua_roots:
                root = self._get_key(hive, root_path)
                if root is None:
                    continue
                for guid_key in root.iter_subkeys():
                    count_key = None
                    try:
                        count_key = guid_key.get_subkey("Count")
                    except Exception:
                        for sk in guid_key.iter_subkeys():
                            if sk.name.lower() == "count":
                                count_key = sk
                    if count_key is None:
                        continue
                    for val in count_key.iter_values():
                        encoded = val.name or ""
                        decoded = rot13_decode(encoded)
                        raw = val.value
                        run_count, last_run = parse_userassist_value(raw)
                        results.append(
                            {
                                "GUID": guid_key.name,
                                "EncodedPath": encoded,
                                "DecodedPath": decoded,
                                "RunCount": run_count,
                                "LastExecuted": last_run,
                                "Suspicious": _is_suspicious_command(decoded),
                            }
                        )
        except Exception:
            return results
        return results

    def parse_all(self, hive_path: Optional[Union[str, Path]] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Run every registry extractor against ``hive_path``.

        Parameters
        ----------
        hive_path : str | Path, optional
            Hive or JSON path.

        Returns
        -------
        dict
            ``sam``, ``run_keys``, ``remote_access``, ``userassist`` lists.
        """
        return {
            "sam": self.parse_sam(hive_path),
            "run_keys": self.parse_run_keys(hive_path),
            "remote_access": self.parse_remote_access_tools(hive_path),
            "userassist": self.parse_userassist(hive_path),
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _open_hive(self, path: Path):
        if self.read_only:
            with ReadOnlyEvidenceFile(path, mode="rb"):
                return RegistryHive(str(path))
        return RegistryHive(str(path))

    @staticmethod
    def _get_key(hive, path: str):
        try:
            return hive.get_key(path)
        except Exception:
            return None

    @staticmethod
    def _key_mtime(key) -> Any:
        try:
            header = getattr(key, "header", None)
            if header is not None and getattr(header, "last_modified", None):
                return parse_timestamp(header.last_modified)
        except Exception:
            return None
        return None

    @staticmethod
    def _rid_from_names_key(name_key) -> Optional[int]:
        # The default value of Names\<user> is the RID (DWORD)
        try:
            for val in name_key.iter_values():
                if val.name in (None, "", "(default)", "Default"):
                    raw = val.value
                    if isinstance(raw, int):
                        return int(raw)
                    if isinstance(raw, (bytes, bytearray)) and len(raw) >= 4:
                        return struct.unpack("<I", raw[:4])[0]
        except Exception:
            return None
        return getattr(name_key, "rid", None)

    @staticmethod
    def _value_bytes(key, name: str) -> bytes:
        try:
            for val in key.iter_values():
                if str(val.name).upper() == name.upper():
                    raw = val.value
                    if isinstance(raw, (bytes, bytearray)):
                        return bytes(raw)
                    if isinstance(raw, int):
                        return struct.pack("<I", raw)
        except Exception:
            return b""
        return b""

    @staticmethod
    def _parse_sam_f(blob: bytes, fallback_rid: Optional[int] = None) -> Dict[str, Any]:
        result = {
            "last_logon": None,
            "password_last_set": None,
            "login_count": 0,
            "flags": 0,
            "rid": fallback_rid,
        }
        if not blob or len(blob) < 0x38:
            return result
        result["last_logon"] = _read_filetime(blob, _SAM_F_LAST_LOGON)
        result["password_last_set"] = _read_filetime(blob, _SAM_F_PASSWORD_SET)
        if len(blob) >= _SAM_F_RID_ALT + 4:
            rid = struct.unpack_from("<I", blob, _SAM_F_RID_ALT)[0]
            if 500 <= rid <= 0xFFFF:
                result["rid"] = rid
        if len(blob) >= _SAM_F_ACB_ALT + 4:
            result["flags"] = struct.unpack_from("<I", blob, _SAM_F_ACB_ALT)[0]
        elif len(blob) >= _SAM_F_ACB + 4:
            result["flags"] = struct.unpack_from("<I", blob, _SAM_F_ACB)[0]
        if len(blob) >= _SAM_F_LOGON_COUNT_ALT + 2:
            result["login_count"] = struct.unpack_from("<H", blob, _SAM_F_LOGON_COUNT_ALT)[0]
        return result

    def _load_json_list(self, path: Path) -> List[Dict[str, Any]]:
        if self.read_only:
            with ReadOnlyEvidenceFile(path, mode="r") as handle:
                payload = json.loads(handle.read())
        else:
            payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            for key in ("accounts", "sam", "records", "values", "entries", "data"):
                if key in payload and isinstance(payload[key], list):
                    return payload[key]
            return [payload]
        return list(payload)


def parse_userassist_value(raw: Any) -> tuple:
    """
    Extract ``(run_count, last_run_timestamp)`` from a UserAssist value blob.

    Parameters
    ----------
    raw : Any
        Bytes, int, or None.

    Returns
    -------
    tuple
        ``(run_count: int, last_run: Timestamp | None)``.
    """
    if raw is None:
        return 0, None
    if isinstance(raw, int):
        return int(raw), None
    if not isinstance(raw, (bytes, bytearray)):
        return 0, None
    blob = bytes(raw)
    run_count = 0
    last_run = None
    if len(blob) >= _USERASSIST_RUNCOUNT_OFF + 4:
        run_count = struct.unpack_from("<I", blob, _USERASSIST_RUNCOUNT_OFF)[0]
    if len(blob) >= _USERASSIST_FILETIME_OFF + 8:
        ticks = struct.unpack_from("<Q", blob, _USERASSIST_FILETIME_OFF)[0]
        last_run = filetime_to_datetime(ticks)
    return int(run_count), last_run


def decode_acb(flags: int) -> List[str]:
    """
    Decode SAM ACB account flags into symbolic names.

    Parameters
    ----------
    flags : int
        ACB bitfield.

    Returns
    -------
    List[str]
        Set flag names.
    """
    return [name for bit, name in ACB_FLAGS.items() if flags & bit]


def _read_filetime(blob: bytes, offset: int):
    if len(blob) < offset + 8:
        return None
    ticks = struct.unpack_from("<Q", blob, offset)[0]
    return filetime_to_datetime(ticks)


def _is_suspicious_command(cmd: str) -> bool:
    text = (cmd or "").lower()
    needles = (
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "appdata",
        "\\temp\\",
        "-enc",
        "-e ",
        "iex",
        "frombase64string",
        "anydesk",
        "teamviewer",
        "rdpwrap",
    )
    return any(n in text for n in needles)


def sam_to_dataframe(records: List[Dict[str, Any]]) -> pd.DataFrame:
    """Convert SAM records to a DataFrame."""
    if not records:
        return pd.DataFrame(
            columns=[
                "RID",
                "Username",
                "CreationTime",
                "LastLogon",
                "PasswordLastSet",
                "LoginCount",
                "AccountFlags",
                "Enabled",
            ]
        )
    return pd.DataFrame(records)
