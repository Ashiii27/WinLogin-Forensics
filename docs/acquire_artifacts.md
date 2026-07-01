# Notes: `acquire_artifacts.py`

---

## 📌 Quick Reference

- **File:** `acquire_artifacts.py`
- **Location:** Project root
- **Type:** Standalone utility script
- **Language:** Python 3.12
- **Dependencies:** Standard library only (no pip packages needed)
- **Privileges:** Requires Administrator
- **Platform:** Windows only
- **Input:** Live Windows system
- **Output:** Timestamped forensic artifacts in `data/samples/`
- **Artifacts Acquired:**
  - **Event Logs:** `Security.evtx`, `System.evtx`, `Application.evtx`
  - **Registry Hives:** `SAM`, `SYSTEM`, `SECURITY`, `SOFTWARE`

---

## 🎯 Purpose

A Python-based forensic artifact acquisition tool that automates the collection of Windows login evidence from a live system. It safely copies Windows Event Logs (Security, System, Application) and Registry Hives (SAM, SYSTEM, SECURITY, SOFTWARE) into a timestamped location for later forensic analysis.

---

## 💡 Why We Built It

### Problem It Solves

Manually acquiring Windows forensic artifacts requires opening Command Prompt as Administrator, remembering exact file paths, running multiple `copy` and `reg save` commands, handling locked files (registry hives cannot be copied normally), and ensuring previous acquisitions are not overwritten.

### Our Solution

One script, one command, all artifacts acquired. This matters because forensic acquisition should be repeatable and consistent. Manual steps introduce human error. Timestamps prove when evidence was acquired, maintaining forensic integrity. Automating this saves 15+ minutes per acquisition.

---

## 🏗 Architecture and Design Decisions

### 1. Modular Function Structure

Instead of one giant function, the script is split into logical parts. Each function does one thing, making the code easier to test, debug, and reuse.

| Function | Responsibility |
|----------|---------------|
| `is_windows()` | OS validation |
| `is_admin()` | Privilege check |
| `get_output_directory()` | Path setup |
| `timestamped_filename()` | Unique naming |
| `format_size()` | Human-readable output |
| `check_system()` | Pre-flight checks |
| `copy_evtx_file()` | Single EVTX copy |
| `save_registry_hive()` | Single hive export |
| `acquire_event_logs()` | All EVTX acquisition |
| `acquire_registry_hives()` | All hives acquisition |
| `print_summary()` | Final report |
| `main()` | Orchestrator |

### 2. Fail-Fast Philosophy

The script exits immediately if the OS is not Windows or if it is not running as Administrator. There is no point wasting time trying to acquire files that will fail anyway.

### 3. Timestamped Files

Every acquired file gets a timestamp appended to its name.

```text
Security_20260701_211519.evtx
```

This ensures previous acquisitions are never overwritten, provides chain-of-custody information, and allows multiple acquisitions to coexist for comparison.

### 4. Verification After Copy

After copying each file, the script checks that the destination file size matches the source file size. Silent data corruption during copy is a real problem, and size verification catches most cases.

---

## 🔧 Technical Components Explained

### Component 1 - Standard Library Imports

```python
import os
import sys
import shutil
import subprocess
import platform
import ctypes
from pathlib import Path
from datetime import datetime
```

| Module | What It Does | Why We Need It |
|--------|--------------|----------------|
| `os` | Operating system interface | General OS operations |
| `sys` | System-specific parameters | Exit with proper error codes |
| `shutil` | High-level file operations | `shutil.copy2()` preserves metadata |
| `subprocess` | Run external commands | Execute `reg.exe` for registry export |
| `platform` | Platform identification | Check if running on Windows |
| `ctypes` | Foreign function interface | Call Windows API for admin check |
| `pathlib.Path` | Modern path handling | Cross-platform, cleaner than `os.path` |
| `datetime` | Date/time handling | Create timestamps for filenames |

### Component 2 - Admin Privilege Check

```python
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False
```

`ctypes.windll` provides access to Windows DLL functions. `shell32` is the Windows `Shell32.dll` library. `IsUserAnAdmin()` is a native Windows API function that returns `1` if the current process has admin privileges, `0` otherwise. The call is wrapped in `try/except` because on non-Windows systems this would crash.

Admin privileges are needed because Event Log files are protected by Windows Security and Registry hives require SYSTEM-level access to export.

### Component 3 - File Copying with `shutil.copy2()`

```python
shutil.copy2(source, dest)
```

| Function | Copies Data | Preserves Metadata | Forensic Value |
|----------|-------------|--------------------|----------------|
| `shutil.copy()` | Yes | No | Loses timestamps |
| `shutil.copy2()` | Yes | Yes | Preserves original modification/access times |

The forensic principle here is to preserve original metadata to maintain evidence integrity. Using `copy2()` ensures the original file timestamps are retained in the copy.

### Component 4 - Registry Export via `subprocess`

Registry hives cannot be copied normally because they are actively in use by Windows. The script uses the built-in `reg.exe` command instead.

```python
cmd = ["reg", "save", f"HKLM\\{hive_name}", str(dest_path), "/y"]

result = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    timeout=60,
    shell=False
)
```

| Parameter | Purpose |
|-----------|---------|
| `["reg", "save", ...]` | Command as list (safer than string) |
| `capture_output=True` | Capture stdout/stderr for error handling |
| `text=True` | Return strings instead of bytes |
| `timeout=60` | Kill the process if it hangs (defensive) |
| `shell=False` | Do not use shell (prevents command injection) |

The `reg save` command exports a registry key to a file. The `/y` flag auto-overwrites if the file exists. Windows' `reg.exe` is a trusted system tool that can safely snapshot live registry hives without corrupting them.

### Component 5 - Path Handling with `pathlib`

```python
# Old way
output_dir = os.path.join(project_root, "data", "samples")

# Modern way (what we use)
output_dir = project_root / "data" / "samples"
output_dir.mkdir(parents=True, exist_ok=True)
```

Pathlib provides cross-platform path handling with cleaner syntax and built-in operations like `.exists()`, `.stat()`, and `.mkdir()`.

### Component 6 - Timestamp Generation

```python
def timestamped_filename(filename):
    name = Path(filename).stem
    ext = Path(filename).suffix
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{name}_{timestamp}{ext}"
```

The format `YYYYMMDD_HHMMSS` is used because it is naturally sortable (newest sorts last), contains no spaces (safe for filenames), and uses no special characters (safe across all operating systems).

### Component 7 - Human-Readable File Sizes

```python
def format_size(size_bytes):
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"
```

The function starts with bytes and progressively divides by 1024 until the value fits within a unit. For example, 20,971,520 bytes becomes "20.00 MB".

### Component 8 - Error Handling Strategy

The script uses three layers of error handling.

Layer 1 handles specific errors first, providing targeted messages for `PermissionError`, `subprocess.TimeoutExpired`, and `FileNotFoundError`.

```python
except PermissionError:
    print("Permission denied")
except subprocess.TimeoutExpired:
    print("Timeout")
except FileNotFoundError:
    print("reg.exe not found")
```

Layer 2 provides a generic fallback for unexpected errors.

```python
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}")
```

Layer 3 wraps the entire `main` function to handle keyboard interrupts and print full tracebacks for debugging.

```python
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)
```

Different errors need different messages. A `PermissionError` tells the user to run as admin. A `TimeoutExpired` tells them the operation took too long.

### Component 9 - Exit Codes

```python
sys.exit(0)    # Success
sys.exit(1)    # General error
sys.exit(130)  # Interrupted by Ctrl+C (standard Unix convention)
```

Exit codes matter because other scripts can check them, CI/CD pipelines rely on them, and they are standard practice in professional tools.

### Component 10 - The `if __name__ == "__main__"` Pattern

```python
if __name__ == "__main__":
    main()
```

When the script is run directly, `main()` executes. When the script is imported by another module, `main()` does not execute. This allows the file to be imported by other scripts (like the Streamlit UI) without triggering acquisition automatically.

---

## 🧠 Key Concepts for Viva

### 1. Digital Forensics Principle: Order of Volatility

Data should be collected in order of how quickly it changes. Registry data (in-memory) is more volatile than event logs (disk-based). The script acquires both efficiently in one pass.

### 2. Chain of Custody

Timestamped filenames create an audit trail. You can prove exactly when each artifact was acquired.

### 3. Non-Destructive Acquisition

The script uses `shutil.copy2` (not move) and `reg save` (not `reg export`). Original artifacts remain untouched on the source system.

### 4. Defensive Programming

The script checks preconditions before acting (admin, OS), verifies results (file size check), handles failures gracefully (`try/except`), and sets timeouts on external commands (prevent hangs).

### 5. Separation of Concerns

Each function has one job. This makes the code testable and maintainable.

---

## 🚀 Limitations and Future Improvements

| Limitation | Future Fix |
|------------|------------|
| No hash verification (MD5/SHA256) | Add hash generation after copy |
| No log file of the acquisition | Add logging to `logs/` folder |
| Does not acquire `NTUSER.DAT` (per-user hives) | Iterate user profiles |
| Does not acquire `Amcache.hve` | Add path to acquisition list |
| Does not handle remote systems | Add SMB/WinRM support |
| No configuration file | Add `config.yaml` for customization |

---

## 🛡️ What Makes This Script Forensic Grade

| Feature | Basic Copy | Our Script |
|---------|------------|------------|
| Handles locked registry files | ❌ No | ✅ Yes |
| Preserves file metadata | ❌ No | ✅ Yes |
| Timestamped output | ❌ No | ✅ Yes |
| Verifies copy integrity | ❌ No | ✅ Yes |
| Admin check | ❌ No | ✅ Yes |
| Human-readable summary | ❌ No | ✅ Yes |
| Error handling | ❌ No | ✅ Yes |
| Reusable and automatable | ❌ No | ✅ Yes |

---

## 📚 Libraries and Standards Used

| Standard or Convention | Where Used |
|------------------------|------------|
| **PEP 8** - Python style guide | Naming, indentation, spacing |
| **Google-style docstrings** | Function documentation |
| **Type-safe subprocess** | `shell=False`, list-form commands |
| **Pathlib over os.path** | Modern path handling |
| **Contextual error handling** | Specific exceptions before generic |
| **Semantic exit codes** | 0 / 1 / 130 |

---

## 🧪 How to Test It

- Run without admin — should fail with clear message
- Run on non-Windows — should fail with clear message
- Run normally — should acquire all files
- Run twice — should create two timestamped copies
- Verify file sizes match sources

---

## 📝 Summary

`acquire_artifacts.py` is a Python-based Windows forensic acquisition tool that automates the collection of Event Logs and Registry hives from a live system. It uses `shutil.copy2()` for file copies (preserving metadata), subprocess with `reg.exe` for locked registry hive exports, ctypes for privilege verification, and pathlib for modern path handling. All acquired artifacts are timestamped and stored in `data/samples/` for later analysis. The script implements defensive error handling, size verification, and follows forensic principles of non-destructive acquisition and chain-of-custody preservation.