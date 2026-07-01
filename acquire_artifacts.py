"""
WinLogin Forensics - Windows Artifact Acquisition Tool
================================================================

Safely acquires forensic artifacts from a live Windows system:
  - Windows Security Event Log (Security.evtx)
  - Registry Hives (SAM, SYSTEM, SECURITY, SOFTWARE)

Requirements:
  - Windows OS
  - Administrator privileges
  - Python 3.10+

Usage:
  Right-click Command Prompt/PowerShell -> Run as Administrator
  Then run: python acquire_artifacts.py

Output:
  All artifacts saved to: data/samples/ with timestamp
"""

import os
import sys
import shutil
import subprocess
import platform
import ctypes
from pathlib import Path
from datetime import datetime


# ============================================================
#  Constants
# ============================================================

EVTX_SOURCES = {
    "Security": r"C:\Windows\System32\winevt\Logs\Security.evtx",
    "System":   r"C:\Windows\System32\winevt\Logs\System.evtx",
    "Application": r"C:\Windows\System32\winevt\Logs\Application.evtx",
}

REGISTRY_HIVES = ["SAM", "SYSTEM", "SECURITY", "SOFTWARE"]

# Only Security.evtx is required — others are optional bonus data
REQUIRED_EVTX = ["Security"]
OPTIONAL_EVTX = ["System", "Application"]


# ============================================================
#  Helper Functions
# ============================================================

def print_banner():
    """Print the tool banner."""
    print()
    print("=" * 64)
    print("  WinLogin Forensics - Artifact Acquisition Tool")
    print("=" * 64)
    print()


def print_section(title):
    """Print a section header."""
    print()
    print(f"[*] {title}")
    print("-" * 64)


def is_windows():
    """Check if the OS is Windows."""
    return platform.system() == "Windows"


def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_output_directory():
    """Create and return the output directory."""
    project_root = Path(__file__).resolve().parent
    output_dir = project_root / "data" / "samples"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def timestamped_filename(filename):
    """Append a timestamp to avoid overwriting previous acquisitions."""
    name = Path(filename).stem
    ext = Path(filename).suffix
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{name}_{timestamp}{ext}"


def format_size(size_bytes):
    """Convert bytes to human-readable size."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


# ============================================================
#  System Checks
# ============================================================

def check_system():
    """Verify system requirements are met."""
    print_section("System Checks")

    # OS check
    if not is_windows():
        print(f"    [X] OS Check FAILED - This tool only runs on Windows")
        print(f"        Current OS: {platform.system()}")
        return False
    print(f"    [OK] OS Check              : {platform.system()} {platform.release()}")

    # Admin check
    if not is_admin():
        print(f"    [X] Admin Check FAILED - Administrator privileges required")
        print()
        print("    Please re-run this script as Administrator:")
        print("      1. Right-click Command Prompt or PowerShell")
        print("      2. Select 'Run as Administrator'")
        print("      3. Navigate to project folder")
        print("      4. Run: python acquire_artifacts.py")
        return False
    print(f"    [OK] Admin Check           : Running as Administrator")

    # Python version check
    py_version = sys.version_info
    if py_version.major < 3 or (py_version.major == 3 and py_version.minor < 10):
        print(f"    [!] Python Check           : {py_version.major}.{py_version.minor} (3.10+ recommended)")
    else:
        print(f"    [OK] Python Check          : {py_version.major}.{py_version.minor}.{py_version.micro}")

    return True


# ============================================================
#  Event Log Acquisition
# ============================================================

def copy_evtx_file(log_name, source_path, output_dir):
    """Copy a single EVTX file safely."""
    source = Path(source_path)

    if not source.exists():
        print(f"    [X] {log_name:12s} - Source not found: {source}")
        return None

    try:
        size = source.stat().st_size
        dest_name = timestamped_filename(source.name)
        dest = output_dir / dest_name

        print(f"    [*] {log_name:12s} - Copying {format_size(size)}...", end=" ", flush=True)
        shutil.copy2(source, dest)

        # Verify copy
        if dest.exists() and dest.stat().st_size == size:
            print("[OK]")
            print(f"        -> {dest.name}")
            return dest
        else:
            print("[FAILED - size mismatch]")
            return None

    except PermissionError:
        print(f"    [X] {log_name:12s} - Permission denied (locked by system)")
        return None
    except Exception as e:
        print(f"    [X] {log_name:12s} - Error: {type(e).__name__}: {e}")
        return None


def acquire_event_logs(output_dir):
    """Acquire all Windows Event Log files."""
    print_section("Acquiring Event Logs")

    acquired = []

    # Required logs
    for name in REQUIRED_EVTX:
        result = copy_evtx_file(name, EVTX_SOURCES[name], output_dir)
        if result:
            acquired.append(result)

    # Optional logs
    for name in OPTIONAL_EVTX:
        result = copy_evtx_file(name, EVTX_SOURCES[name], output_dir)
        if result:
            acquired.append(result)

    return acquired


# ============================================================
#  Registry Hive Acquisition
# ============================================================

def save_registry_hive(hive_name, output_dir):
    """Export a registry hive using reg.exe."""
    dest_name = timestamped_filename(hive_name)
    dest_path = output_dir / dest_name

    cmd = [
        "reg", "save",
        f"HKLM\\{hive_name}",
        str(dest_path),
        "/y"
    ]

    print(f"    [*] {hive_name:10s} - Exporting HKLM\\{hive_name}...", end=" ", flush=True)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            shell=False
        )

        if result.returncode == 0 and dest_path.exists():
            size = dest_path.stat().st_size
            print(f"[OK] ({format_size(size)})")
            print(f"        -> {dest_path.name}")
            return dest_path
        else:
            print("[FAILED]")
            if result.stderr:
                print(f"        Error: {result.stderr.strip()}")
            return None

    except subprocess.TimeoutExpired:
        print("[FAILED - timeout after 60s]")
        return None
    except FileNotFoundError:
        print("[FAILED - reg.exe not found in PATH]")
        return None
    except Exception as e:
        print(f"[FAILED]")
        print(f"        Error: {type(e).__name__}: {e}")
        return None


def acquire_registry_hives(output_dir):
    """Acquire all specified registry hives."""
    print_section("Acquiring Registry Hives")

    acquired = []
    for hive in REGISTRY_HIVES:
        result = save_registry_hive(hive, output_dir)
        if result:
            acquired.append(result)

    return acquired


# ============================================================
#  Summary Report
# ============================================================

def print_summary(evtx_files, registry_files, output_dir):
    """Print acquisition summary."""
    print()
    print("=" * 64)
    print("  Acquisition Summary")
    print("=" * 64)

    total_files = len(evtx_files) + len(registry_files)
    total_size = 0

    print(f"    Event Log Files    : {len(evtx_files)}")
    for f in evtx_files:
        size = f.stat().st_size
        total_size += size
        print(f"        - {f.name:60s} ({format_size(size)})")

    print(f"    Registry Hives     : {len(registry_files)}")
    for f in registry_files:
        size = f.stat().st_size
        total_size += size
        print(f"        - {f.name:60s} ({format_size(size)})")

    print(f"    Total Files        : {total_files}")
    print(f"    Total Size         : {format_size(total_size)}")
    print(f"    Output Location    : {output_dir}")
    print("=" * 64)

    if total_files > 0:
        print()
        print("  [OK] Acquisition complete!")
        print()
        print("  Next steps:")
        print("    1. Verify files in data/samples/")
        print("    2. Run exploration scripts to understand structure")
        print("    3. Start Phase 1 - Core EVTX parser")
        print()
    else:
        print()
        print("  [X] No files were acquired. Check errors above.")
        print()


# ============================================================
#  Main
# ============================================================

def main():
    """Main execution flow."""
    print_banner()

    # 1. System checks
    if not check_system():
        print()
        print("Acquisition aborted due to failed system checks.")
        sys.exit(1)

    # 2. Setup output directory
    output_dir = get_output_directory()
    print(f"    [OK] Output Directory      : {output_dir}")

    # 3. Acquire event logs
    evtx_files = acquire_event_logs(output_dir)

    # 4. Acquire registry hives
    registry_files = acquire_registry_hives(output_dir)

    # 5. Print summary
    print_summary(evtx_files, registry_files, output_dir)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print()
        print("[!] Acquisition interrupted by user")
        sys.exit(130)
    except Exception as e:
        print()
        print(f"[X] Unexpected error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)