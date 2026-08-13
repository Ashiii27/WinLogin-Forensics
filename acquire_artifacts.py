#!/usr/bin/env python3
"""
WinLogin Forensics - Artifact Acquisition
=========================================
Acquire EVTX logs and registry hives from a live Windows system without
locking the originals.

Strategy (in order):
  1. Volume Shadow Copy (vssadmin) when available
  2. ``reg.exe save`` for HKLM hives (works against locked files)
  3. Direct copy for EVTX when the file is not locked

Every acquired file is hashed with SHA-256 immediately after the copy
and appended to a chain-of-custody log (``custody_log.json``).

Paths are never hardcoded by callers — pass ``--output-dir``.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


EVTX_SOURCES = {
    "Security": r"C:\Windows\System32\winevt\Logs\Security.evtx",
    "System": r"C:\Windows\System32\winevt\Logs\System.evtx",
    "Sysmon": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
    "PowerShell": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
}

REGISTRY_HIVES = ["SAM", "SYSTEM", "SECURITY", "SOFTWARE"]


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    """
    Compute SHA-256 of ``path`` immediately after acquisition.

    Parameters
    ----------
    path : Path
        Newly copied evidence file.

    Returns
    -------
    str
        Hex digest.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_windows() -> bool:
    """Return True when running on Windows."""
    return platform.system() == "Windows"


def is_admin() -> bool:
    """Return True when the process has Administrator rights."""
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class CustodyLog:
    """Append-only chain-of-custody record for an acquisition run."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.path = output_dir / "custody_log.json"
        self.record: Dict = {
            "started_at": utc_now(),
            "completed_at": None,
            "operator": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
            "hostname": platform.node(),
            "command_line": " ".join(sys.argv),
            "platform": platform.platform(),
            "actions": [],
            "files": [],
        }

    def action(self, name: str, detail: str) -> None:
        """Append a timestamped action entry."""
        self.record["actions"].append({"time": utc_now(), "action": name, "detail": detail})

    def add_file(self, path: Path, source: str) -> str:
        """
        Hash ``path`` and append it to the custody file list.

        Parameters
        ----------
        path : Path
            Acquired file.
        source : str
            Origin description.

        Returns
        -------
        str
            SHA-256 hex digest.
        """
        digest = sha256_file(path)
        self.record["files"].append(
            {
                "path": str(path),
                "filename": path.name,
                "source": source,
                "sha256": digest,
                "size_bytes": path.stat().st_size,
                "hashed_at": utc_now(),
            }
        )
        self.action("hash", f"{path.name} sha256={digest}")
        return digest

    def save(self) -> Path:
        """Persist ``custody_log.json``. Returns the path written."""
        self.record["completed_at"] = utc_now()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.record, indent=2), encoding="utf-8")
        return self.path


def _run(cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)


def try_vss_copy(source: Path, dest: Path) -> bool:
    """
    Attempt to copy ``source`` via a persistent VSS snapshot.

    Parameters
    ----------
    source, dest : Path
        Source evidence and destination copy.

    Returns
    -------
    bool
        True on success.
    """
    if not is_windows():
        return False
    try:
        created = _run(["vssadmin", "list", "shadows"], timeout=30)
        if created.returncode != 0:
            return False
        # Fallback: use wmic shadowcopy create then copy
        create = _run(
            ["wmic", "shadowcopy", "call", "create", f"Volume={source.drive}\\"],
            timeout=120,
        )
        if create.returncode != 0:
            return False
        shutil.copy2(source, dest)
        return dest.exists()
    except Exception:
        return False


def copy_evtx(log_name: str, source: Path, output_dir: Path, custody: CustodyLog) -> Optional[Path]:
    """Copy one EVTX file, hash it, and record custody."""
    if not source.exists():
        custody.action("skip", f"{log_name} source missing: {source}")
        return None
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = output_dir / f"{source.stem}_{stamp}{source.suffix}"
    try:
        copied = False
        try:
            shutil.copy2(source, dest)
            copied = dest.exists()
        except PermissionError:
            copied = try_vss_copy(source, dest)
        if not copied:
            custody.action("fail", f"{log_name} copy failed")
            return None
        custody.add_file(dest, source=str(source))
        custody.action("acquire", f"{log_name} -> {dest.name}")
        return dest
    except Exception as exc:
        custody.action("fail", f"{log_name}: {exc}")
        return None


def save_hive(hive_name: str, output_dir: Path, custody: CustodyLog) -> Optional[Path]:
    """Export HKLM\\<hive> with reg.exe and hash the result."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = output_dir / f"{hive_name}_{stamp}"
    cmd = ["reg", "save", rf"HKLM\{hive_name}", str(dest), "/y"]
    try:
        result = _run(cmd, timeout=90)
        if result.returncode != 0 or not dest.exists():
            custody.action("fail", f"reg save {hive_name}: {result.stderr.strip()}")
            return None
        custody.add_file(dest, source=rf"HKLM\{hive_name}")
        custody.action("acquire", f"{hive_name} -> {dest.name}")
        return dest
    except FileNotFoundError:
        custody.action("fail", "reg.exe not found")
        return None
    except Exception as exc:
        custody.action("fail", f"{hive_name}: {exc}")
        return None


def acquire(
    output_dir: Path,
    evtx: Optional[List[str]] = None,
    hives: Optional[List[str]] = None,
    ntuser: Optional[Path] = None,
) -> Dict:
    """
    Run the acquisition pipeline.

    Parameters
    ----------
    output_dir : Path
        Destination directory (created if needed).
    evtx : list of str, optional
        Subset of EVTX_SOURCES keys to collect.
    hives : list of str, optional
        Subset of REGISTRY_HIVES to export.
    ntuser : Path, optional
        Offline NTUSER.DAT to copy.

    Returns
    -------
    dict
        Custody record.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    custody = CustodyLog(output_dir)
    custody.action("start", f"output={output_dir}")

    for name in evtx or list(EVTX_SOURCES):
        copy_evtx(name, Path(EVTX_SOURCES[name]), output_dir, custody)
    for hive in hives or list(REGISTRY_HIVES):
        save_hive(hive, output_dir, custody)
    if ntuser and ntuser.exists():
        dest = output_dir / f"NTUSER_{datetime.now().strftime('%Y%m%d_%H%M%S')}.DAT"
        shutil.copy2(ntuser, dest)
        custody.add_file(dest, source=str(ntuser))

    custody.save()
    return custody.record


def main(argv=None) -> int:
    """CLI entry point. Returns process exit code."""
    parser = argparse.ArgumentParser(description="Acquire Windows forensic artifacts")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Destination directory (default: <repo>/data/samples)",
    )
    parser.add_argument("--evtx", nargs="*", default=None, help="EVTX names to collect")
    parser.add_argument("--hives", nargs="*", default=None, help="HKLM hive names to export")
    parser.add_argument("--ntuser", type=Path, default=None, help="NTUSER.DAT to copy")
    parser.add_argument("--force", action="store_true", help="Skip Windows/admin checks (for tests)")
    args = parser.parse_args(argv)

    output = args.output_dir or (Path(__file__).resolve().parent / "data" / "samples")

    if not args.force:
        if not is_windows():
            print("This acquisition helper is intended for live Windows systems.")
            print("Re-run on Windows as Administrator, or pass --force for a dry structure.")
            output.mkdir(parents=True, exist_ok=True)
            log = CustodyLog(output)
            log.action("abort", f"non-Windows host {platform.system()}")
            log.save()
            return 2
        if not is_admin():
            print("Administrator privileges are required.")
            return 1

    record = acquire(output, evtx=args.evtx, hives=args.hives, ntuser=args.ntuser)
    print(f"Acquired {len(record['files'])} file(s). Custody log: {output / 'custody_log.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
