<div align="center">

# WinLogin Forensics

### Windows Authentication Artifact Extraction, Correlation & Analysis Framework

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.37.0-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)]()
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active%20Development-f59e0b?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

<br/>

> Parse Windows Security Event Logs and Registry hives to reconstruct  
> **who logged in, when, from where, and whether it was suspicious** —  
> all from a single interactive forensic dashboard.

<br/>

[Quick Start](#-quick-start) · [Features](#-features) · [Architecture](#-architecture) · [Event IDs](#-covered-event-ids) · [Documentation](#-documentation) · [Contributing](#-contributing)

<br/>

> ⚠️ **This project is under active development.** Core architecture and documentation are complete. Parser and analysis modules are in progress. See the [Development Status](#-development-status) section for the current state.

</div>

---

## The Problem

Windows records every authentication event — logons, logoffs, failed attempts, privilege assignments, RDP sessions — across binary `.evtx` log files and locked Registry hives. The data is all there. Getting to it is the problem.

Manual analysis using Event Viewer means no session correlation, no anomaly detection, and no timeline view. Enterprise tools like Splunk or commercial forensic suites solve this but cost thousands of dollars and aren't built for focused login artifact work.

**WinLogin Forensics** is a purpose-built, open-source alternative that parses these artifacts, correlates sessions, flags suspicious patterns, and surfaces everything through a clean web interface — in minutes instead of hours.

---

## Features

| | |
|---|---|
| 🗂️ **EVTX Parsing** — Extracts 20+ login-related Event IDs from `Security.evtx` with full field detail and timezone-aware timestamps | 🔗 **Session Correlation** — Links logon (4624) and logoff (4634/4647) events by `TargetLogonId` to reconstruct complete login sessions with durations |
| 🚨 **Anomaly Detection** — Automated detection of brute force, lateral movement, privilege escalation, after-hours logins, and account lockouts | 🗄️ **Registry Forensics** — Parses offline SAM, SYSTEM, and SECURITY hives for user account state, last login times, bad password counts, and cached credentials |
| 📈 **Timeline Visualization** — Interactive Plotly timeline with filters by user, event type, logon type, and date range | 📑 **Report Generation** — Auto-generated HTML and PDF forensic reports with executive summary, event statistics, session analysis, and embedded charts |
| 🧭 **Logon Type Classification** — Every login event classified by mechanism (Interactive, RDP, Network, Service, Batch, etc.) | 🌐 **Web Interface** — Multi-page Streamlit dashboard with file upload, real-time analysis, and CSV export. No CLI knowledge required |

---

## Quick Start

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | |
| OS | Windows | Required for live Registry access |
| Admin Privileges | — | Required to read `Security.evtx` on a live system |
| wkhtmltopdf | Latest | Required for PDF report generation — [Download](https://wkhtmltopdf.org/downloads.html) |

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Ashiii27/WinLogin-Forensics.git
cd WinLogin-Forensics

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux / macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the application
streamlit run src/app.py
```

Open `http://localhost:8501` in your browser.

**Windows one-click launch:**
```bash
run.bat
```

### Input Files

| File | Default Location | Notes |
|---|---|---|
| `Security.evtx` | `C:\Windows\System32\winevt\Logs\Security.evtx` | Requires admin rights to copy on a live system |
| `SAM` hive | `C:\Windows\System32\config\SAM` | Locked on a live system — acquire via forensic tool or offline boot |
| `SYSTEM` hive | `C:\Windows\System32\config\SYSTEM` | Same as above |
| `SECURITY` hive | `C:\Windows\System32\config\SECURITY` | Same as above |

> 💡 Sample `.evtx` and Registry hive files with simulated/anonymized data are provided in `data/samples/` for testing without a live system.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     Streamlit Web UI                     │
│                                                          │
│   Home · Event Logs · Registry · Sessions · Anomalies   │
│                  Timeline · Report                       │
└──────────────────────────┬───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│                     Analysis Engine                      │
│                                                          │
│        Anomaly Detector        Statistics Engine         │
└──────────────────────────┬───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│                      Parsing Layer                       │
│                                                          │
│     EVTX Parser    Registry Parser    Session Correlator │
│                    SAM / SYS / SEC                       │
└──────────────────────────┬───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│                       Input Files                        │
│                                                          │
│         Security.evtx  ·  SAM  ·  SYSTEM  ·  SECURITY   │
└──────────────────────────────────────────────────────────┘
```

---

## Covered Event IDs

### Authentication & Session Events

| Event ID | Description | Category |
|---|---|---|
| 4624 | Successful logon | Authentication |
| 4625 | Failed logon attempt | Authentication |
| 4634 | Account logoff | Session |
| 4647 | User-initiated logoff | Session |
| 4648 | Logon with explicit credentials | ⚠️ Suspicious |
| 4672 | Special privileges assigned to new logon | Privilege |
| 4778 | Remote Desktop session reconnected | RDP |
| 4779 | Remote Desktop session disconnected | RDP |
| 4800 | Workstation locked | Session |
| 4801 | Workstation unlocked | Session |

### Account Management Events

| Event ID | Description | Category |
|---|---|---|
| 4720 | User account created | Account |
| 4722 | User account enabled | Account |
| 4723 | Password change attempted | Account |
| 4724 | Password reset attempted | Account |
| 4725 | User account disabled | Account |
| 4726 | User account deleted | Account |
| 4728 | Member added to security-enabled global group | Group |
| 4732 | Member added to security-enabled local group | Group |
| 4740 | User account locked out | Account |
| 4767 | User account unlocked | Account |

---

## Logon Types

| Type | Name | Description |
|---|---|---|
| 2 | Interactive | Direct keyboard login at the machine |
| 3 | Network | Login over network (SMB, file shares) |
| 4 | Batch | Scheduled task or batch job |
| 5 | Service | Windows service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Network login with plaintext credentials — ⚠️ high risk |
| 9 | NewCredentials | RunAs with alternate credentials |
| 10 | RemoteInteractive | Remote Desktop Protocol (RDP) |
| 11 | CachedInteractive | Login using cached domain credentials |
| 12 | CachedRemoteInteractive | Cached RDP login |
| 13 | CachedUnlock | Workstation unlock using cached credentials |

---

## Anomaly Detection

| Anomaly | Detection Logic | Severity |
|---|---|---|
| Brute Force Attack | 5+ failed logons (4625) within a 5-minute window | 🔴 High |
| After-Hours Login | Successful logon outside 08:00–18:00 | 🟡 Medium |
| Admin Privilege Escalation | Event 4672 on a non-privileged account | 🔴 High |
| Lateral Movement | Explicit credential use (4648) — often indicates pass-the-hash | 🔴 High |
| Account Lockout | Event 4740 triggered | 🟡 Medium |
| RDP from Unknown Source | Event 4778 originating from a new or unusual IP | 🟡 Medium |
| New Account Created | Event 4720 during the investigation window | 🟠 High |
| Mass Account Modification | Multiple 4720/4726 events within a short timeframe | 🔴 High |
| Repeated Unlock Attempts | Multiple 4801 events in a short window | 🟡 Medium |

---

## Report Structure

Auto-generated reports include:

1. **Case Information** — Case number, investigator name, analysis date, system metadata
2. **Executive Summary** — Key findings in plain language for non-technical stakeholders
3. **Event Statistics** — Total event count, breakdown by type, user, and logon type
4. **Session Analysis** — Correlated login/logoff pairs with duration and orphaned sessions
5. **Anomaly Findings** — All flagged activity with context, timestamps, and severity
6. **Full Event Table** — Complete parsed event log with all extracted fields
7. **Timeline Chart** — Embedded interactive visual timeline
8. **Appendix** — Raw data reference and acquisition notes

Export formats: **HTML** and **PDF**

---

## Project Structure

```
WinLogin-Forensics/
│
├── src/
│   ├── parsers/
│   │   ├── evtx_parser.py          # Security.evtx parsing
│   │   ├── registry_parser.py      # SAM / SYSTEM / SECURITY hive parsing
│   │   └── session_correlator.py   # Logon–logoff session reconstruction
│   │
│   ├── analysis/
│   │   ├── anomaly_detector.py     # Suspicious pattern detection
│   │   └── statistics.py           # Aggregation and summary statistics
│   │
│   ├── report/
│   │   ├── html_generator.py       # Jinja2-based HTML report
│   │   ├── pdf_generator.py        # pdfkit PDF export
│   │   └── templates/
│   │       └── report_template.html
│   │
│   ├── utils/
│   │   ├── time_utils.py           # Timezone normalization
│   │   └── helpers.py
│   │
│   ├── ui/
│   │   ├── pages/
│   │   │   ├── home.py
│   │   │   ├── event_logs.py
│   │   │   ├── registry.py
│   │   │   ├── sessions.py
│   │   │   ├── anomalies.py
│   │   │   ├── timeline.py
│   │   │   └── report.py
│   │   └── components/
│   │       ├── sidebar.py
│   │       ├── charts.py
│   │       └── tables.py
│   │
│   └── app.py                      # Streamlit entrypoint
│
├── data/
│   ├── samples/                    # Anonymized test artifacts
│   └── README.md
│
├── output/
│   ├── reports/
│   └── exports/
│
├── docs/
│   ├── methodology.md
│   ├── user_guide.md
│   └── event_ids.md
│
├── tests/
│   ├── test_evtx_parser.py
│   ├── test_registry_parser.py
│   └── test_anomaly_detector.py
│
├── requirements.txt
├── run.bat
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.10+ |
| Web Interface | Streamlit 1.37 |
| EVTX Parsing | python-evtx, xmltodict |
| Registry Parsing | regipy, python-registry |
| Data Processing | pandas |
| Visualization | Plotly |
| Report Generation | Jinja2, pdfkit |
| Utilities | python-dateutil, colorama |

---

## Development Status

**Current phase:** Architecture & Documentation complete — active implementation in progress.

| Module | Status |
|---|---|
| Project structure & documentation | ✅ Complete |
| EVTX parser — core events (4624, 4625, 4634, 4647) | 🔄 In Progress |
| EVTX parser — extended events (4648, 4672, 4720, 4740+) | ⏳ Planned |
| Session correlator | ⏳ Planned |
| Registry parser (SAM, SYSTEM, SECURITY) | ⏳ Planned |
| Anomaly detection engine | ⏳ Planned |
| Statistics engine | ⏳ Planned |
| Streamlit web UI | ⏳ Planned |
| Timeline visualization | ⏳ Planned |
| HTML report generator | ⏳ Planned |
| PDF report generator | ⏳ Planned |
| Unit tests | ⏳ Planned |
| Sample data files | ⏳ Planned |

---

## Documentation

| Document | Description |
|---|---|
| [Methodology](docs/methodology.md) | Forensic approach, artifact sources, and analysis methodology |
| [User Guide](docs/user_guide.md) | Step-by-step usage instructions with screenshots |
| [Event ID Reference](docs/event_ids.md) | All covered Event IDs with field-level explanations |
| [Sample Data Guide](data/README.md) | How to safely acquire test artifacts from a Windows system |

---

## Contributing

Contributions are welcome. If you're working in digital forensics, security research, or Python development, there are open areas across parsers, anomaly detection logic, and UI.

**To contribute:**

```bash
# Fork the repo, then:
git clone https://github.com/YOUR_USERNAME/WinLogin-Forensics.git
git checkout -b feature/your-feature-name

# After your changes:
git commit -m "feat: describe your change"
git push origin feature/your-feature-name
# Open a Pull Request
```

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting. For bugs or feature requests, open an [Issue](https://github.com/Ashiii27/WinLogin-Forensics/issues).

---

## Responsible Use

This tool is designed for **authorized forensic investigation only** — incident response, academic research, and security analysis on systems you own or have explicit written permission to examine.

**Do not use WinLogin Forensics to access or analyze systems without authorization.** Unauthorized access to computer systems is illegal under applicable laws including the Computer Fraud and Abuse Act (CFAA) and equivalents in other jurisdictions. The authors accept no liability for misuse.

---

## Acknowledgements

- [python-evtx](https://github.com/williballenthin/python-evtx) by Willi Ballenthin — Windows Event Log parsing library
- [regipy](https://github.com/mkorman90/regipy) by Maxim Korman — offline Registry hive parsing
- Windows Security Log Encyclopedia — [ultimatewindowssecurity.com](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- MITRE ATT&CK Framework — lateral movement and persistence technique mapping

---

## Author

**Ashish Kumar**  
[github.com/Ashiii27](https://github.com/Ashiii27) · [linkedin.com/in/ashiii27](https://linkedin.com/in/ashiii27)

---

## License

Released under the [MIT License](LICENSE).  
© 2026 Ashish Kumar
