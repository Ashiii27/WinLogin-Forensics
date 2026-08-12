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

> Parse Windows Security Event Logs, Registry hives, Sysmon, and PowerShell logs to reconstruct
> **who logged in, when, from where, and what they did next** —
> enriched with ML anomaly detection, MITRE ATT&CK mapping, and forensic-grade chain-of-custody.

<br/>

[Quick Start](#-quick-start) · [Features](#-features) · [Architecture](#-architecture) · [Event IDs](#-covered-event-ids) · [Development Status](#-development-status) · [Documentation](#-documentation) · [Contributing](#-contributing)

<br/>

> ⚠️ **This project is under active development.** Core architecture and documentation are complete. See [Development Status](#-development-status) for the current phase-by-phase progress.

</div>

---

## The Problem

Windows records every authentication event — logons, logoffs, failed attempts, privilege assignments, RDP sessions, Kerberos ticket requests, service installations, scheduled tasks — across binary `.evtx` log files, locked Registry hives, Sysmon channels, and PowerShell operational logs. The data is all there. Getting to it is the problem.

Manual analysis using Event Viewer means no session correlation, no anomaly detection, no timeline view, and no chain-of-custody. Enterprise tools like Splunk or commercial forensic suites solve this, but cost thousands of dollars and aren't built for focused login artifact work.

**WinLogin Forensics** is a purpose-built, open-source alternative that:
- Parses all relevant log sources into a unified timeline
- Correlates sessions across event types, log channels, and registry artifacts
- Flags suspicious patterns using rule-based and ML-based detectors with SHAP explainability
- Maps every finding to a MITRE ATT&CK technique ID
- Generates forensically sound reports with chain-of-custody, hash, and optional RFC 3161 timestamp

---

## Features

| | |
|---|---|
| 🗂️ **EVTX Parsing** — 35+ Event IDs from Security, System, Sysmon, and PowerShell channels | 🔗 **Session Correlation** — Links logon/logoff by `TargetLogonId`; incremental streaming mode for real-time |
| 🚨 **Anomaly Detection** — Brute force, credential stuffing, lateral movement, privilege escalation, after-hours logins, Kerberoasting, AS-REP roasting | 🛡️ **Anti-Forensic Detection** — Log-clearing (1102/104), timestamp manipulation (4616), RecordID sequence gaps, sudden volume drops |
| 🗄️ **Registry Forensics** — SAM last-logon + creation time per RID, SOFTWARE Run keys (remote-access tool detection), UserAssist from NTUSER.DAT | 🔭 **Sysmon Correlation** — Process creation (EID 1), network connections (EID 3), file creation (EID 11), DNS queries (EID 22), mapped to authenticated sessions |
| 🐚 **PowerShell Log Correlation** — Script block logging (4103/4104) correlated against flagged sessions | 🤖 **ML Models** — IsolationForest (swept) + One-Class SVM baseline + GNN (PyTorch Geometric) for lateral-movement detection; ROC/AUC/PR curves reported |
| 🗺️ **MITRE ATT&CK Mapping** — Every detection rule keyed to a technique ID; coverage matrix generated for reports and the research paper | 🔍 **SHAP Explainability** — Feature-importance and confidence scores surfaced on every flagged anomaly |
| 🌍 **Geographic Features** — IP geolocation lookup + impossible-travel detection (distance/time check between consecutive logons) | ⏱️ **Real-Time Mode** — EventLogWatcher subscription-based live extraction with SMTP alerting on critical-severity detections |
| 📑 **Forensic Reports** — HTML + PDF with chain-of-custody log, SHA-256 hash, optional RFC 3161 timestamp | 🔒 **Read-Only Evidence Handling** — Syscall-level write-attempt detection and abort on source evidence files |
| ⚖️ **Benchmarking Harness** — Runs Chainsaw, Hayabusa, DeepBlueCLI, and Plaso against identical scenarios for side-by-side comparison | 📈 **Evaluation Harness** — Labeled corpus pipeline (Atomic Red Team + EVTX-ATTACK-SAMPLES), train/test split, mean ± std metrics over randomized splits |

---

## Quick Start

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | |
| OS | Windows | Required for live Registry access and EventLogWatcher |
| Admin Privileges | — | Required to read `Security.evtx` and export Registry hives on a live system |
| SYSTEM Privileges | — | Required for `RegSaveKeyEx` (live hive acquisition) — see [docs/acquire_artifacts.md](docs/acquire_artifacts.md) |
| wkhtmltopdf | Latest | Required for PDF report generation — [Download](https://wkhtmltopdf.org/downloads.html) |
| Sysmon | Optional | Install on the target system for process/network/DNS correlation |

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

**CLI usage:**
```bash
# Batch analysis
python -m src.cli.main --evtx path/to/Security.evtx --sam path/to/SAM --report output/

# Real-time monitoring (requires admin; EventLogWatcher)
python src/live/live_monitor.py --alert-email soc@example.com

# Run with forensic soundness flags
python -m src.cli.main --evtx Security.evtx --readonly --sign --timestamp
```

### Input Files

| File | Default Location | Notes |
|---|---|---|
| `Security.evtx` | `C:\Windows\System32\winevt\Logs\Security.evtx` | Requires admin rights to copy on a live system |
| `System.evtx` | `C:\Windows\System32\winevt\Logs\System.evtx` | Needed for EID 7045, 104 |
| `Microsoft-Windows-Sysmon%4Operational.evtx` | `C:\Windows\System32\winevt\Logs\` | Optional — requires Sysmon installed |
| `Microsoft-Windows-PowerShell%4Operational.evtx` | `C:\Windows\System32\winevt\Logs\` | Optional — requires Script Block Logging enabled |
| `SAM` hive | `C:\Windows\System32\config\SAM` | Locked on a live system — acquire via `acquire_artifacts.py` or offline boot |
| `SYSTEM` hive | `C:\Windows\System32\config\SYSTEM` | Same as above |
| `SECURITY` hive | `C:\Windows\System32\config\SECURITY` | Same as above |
| `NTUSER.DAT` | `C:\Users\<username>\NTUSER.DAT` | Per-user; needed for UserAssist correlation |

> 💡 Sample `.evtx` and Registry hive files with simulated/anonymized data are provided in `data/samples/` for testing without a live system.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Streamlit Web UI                         │
│                                                                 │
│  Home · Events · Registry · Sessions · Anomalies · Timeline     │
│  ATT&CK Matrix · Real-Time · Benchmark · Report                 │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                        Analysis Engine                          │
│                                                                 │
│   Anomaly Detector   Feature Engineer   ML Models (IF/SVM/GNN)  │
│   Correlator         Auth Graph         MITRE Mapper            │
│   Statistics         SHAP Explainer                             │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                         Parsing Layer                           │
│                                                                 │
│  EVTX Parser     Anti-Forensic Detector    Session Correlator   │
│  Registry Parser  Sysmon Parser            PowerShell Parser    │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                          Input Sources                          │
│                                                                 │
│  Security.evtx · System.evtx · Sysmon.evtx · PowerShell.evtx    │
│  SAM · SYSTEM · SECURITY · NTUSER.DAT                           │
└─────────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                      Forensic Soundness                         │
│                                                                 │
│  Chain-of-Custody Log · SHA-256 Report Hash · RFC 3161 TSA      │
│  Read-Only Evidence Enforcement · Digital Report Signing        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Covered Event IDs

### Authentication & Session Events

| Event ID | Channel | Description | Category |
|---|---|---|---|
| 4624 | Security | Successful logon | Authentication |
| 4625 | Security | Failed logon attempt | Authentication |
| 4634 | Security | Account logoff | Session |
| 4647 | Security | User-initiated logoff | Session |
| 4648 | Security | Logon with explicit credentials | ⚠️ Lateral Movement |
| 4672 | Security | Special privileges assigned to new logon | Privilege |
| 4778 | Security | Remote Desktop session reconnected | RDP |
| 4779 | Security | Remote Desktop session disconnected | RDP |
| 4800 | Security | Workstation locked | Session |
| 4801 | Security | Workstation unlocked | Session |

### Kerberos Events

| Event ID | Channel | Description | Category |
|---|---|---|---|
| 4768 | Security | Kerberos TGT requested | Kerberos |
| 4769 | Security | Kerberos service ticket requested | Kerberos |
| 4771 | Security | Kerberos pre-authentication failed | Kerberos |
| 4776 | Security | NTLM credential validation | NTLM |

### Account Management Events

| Event ID | Channel | Description | Category |
|---|---|---|---|
| 4720 | Security | User account created | Account |
| 4722 | Security | User account enabled | Account |
| 4723 | Security | Password change attempted | Account |
| 4724 | Security | Password reset attempted | Account |
| 4725 | Security | User account disabled | Account |
| 4726 | Security | User account deleted | Account |
| 4728 | Security | Member added to security-enabled global group | Group |
| 4732 | Security | Member added to security-enabled local group | Group |
| 4740 | Security | User account locked out | Account |
| 4756 | Security | Member added to security-enabled universal group | Group |
| 4767 | Security | User account unlocked | Account |

### Privilege & Persistence Events

| Event ID | Channel | Description | Category |
|---|---|---|---|
| 4698 | Security | Scheduled task created | Persistence |
| 7045 | System | New service installed | Persistence |

### Anti-Forensic Events

| Event ID | Channel | Description | Category |
|---|---|---|---|
| 1102 | Security | Security audit log cleared | ⚠️ Anti-Forensic |
| 104 | System | System log cleared | ⚠️ Anti-Forensic |
| 4616 | Security | System time changed | ⚠️ Timestamp Manipulation |

### Sysmon Events (optional — requires Sysmon)

| Event ID | Description | Category |
|---|---|---|
| 1 | Process creation | Process |
| 3 | Network connection | Network |
| 11 | File created | File |
| 22 | DNS query | Network |

### PowerShell Events (optional — requires Script Block Logging)

| Event ID | Description | Category |
|---|---|---|
| 4103 | Module logging | PowerShell |
| 4104 | Script block logging | PowerShell |

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

### Rule-Based Detections

| Anomaly | Detection Logic | MITRE Technique | Severity |
|---|---|---|---|
| Brute Force Attack | 5+ failed logons (4625) within 5 minutes | T1110.001 | 🔴 High |
| Credential Stuffing | High failure rate, broad username spread | T1110.004 | 🔴 High |
| Pass-the-Hash / Explicit Credential | Event 4648 — alternate credentials used | T1550.002 | 🔴 High |
| Kerberoasting | 4769 with RC4 encryption (downgrade) | T1558.003 | 🔴 High |
| Kerberos Burst | 4768/4769 burst from one source IP | T1558 | 🟠 Medium |
| AS-REP Roasting | 4771 pre-auth failure pattern | T1558.004 | 🟠 Medium |
| Admin Privilege Escalation | Event 4672 on non-privileged account | T1078.002 | 🔴 High |
| Lateral Movement | Type 3/10 logon from unusual source | T1021 | 🔴 High |
| New Account Created | Event 4720 in investigation window | T1136.001 | 🟠 High |
| Mass Account Modification | Multiple 4720/4726 in short timeframe | T1098 | 🔴 High |
| Group Membership Change | 4732/4756 adding account to privileged group | T1098.007 | 🟠 Medium |
| Scheduled Task Created | Event 4698 | T1053.005 | 🟠 Medium |
| New Service Installed | Event 7045 | T1543.003 | 🟠 Medium |
| After-Hours Login | Successful logon outside 08:00–18:00 | T1078 | 🟡 Medium |
| Account Lockout | Event 4740 triggered | T1110 | 🟡 Medium |
| RDP from Unknown Source | Event 4778 from new/unusual IP | T1021.001 | 🟡 Medium |
| Repeated Unlock Attempts | Multiple 4801 in short window | T1110 | 🟡 Medium |
| Impossible Travel | Two logons from geographically distant IPs within impossible transit time | T1078 | 🔴 High |

### Anti-Forensic Detections

| Anomaly | Detection Logic | MITRE Technique | Severity |
|---|---|---|---|
| Log Clearing | Event 1102 (Security) or 104 (System) | T1070.001 | 🔴 High |
| Timestamp Manipulation | Event 4616 (system time change) cross-reference | T1070.006 | 🔴 High |
| Selective Record Deletion | EVTX RecordID sequence gap detected | T1070.001 | 🔴 High |
| Log Volume Drop | Sudden drop in events-per-hour vs baseline | T1070 | 🟠 Medium |
| SAM Record Mismatch | SAM creation time vs 4720 discrepancy | T1070 | 🔴 High |

### ML-Based Detections

| Model | Purpose | Output |
|---|---|---|
| IsolationForest | General authentication anomaly scoring (contamination factor determined by hyperparameter sweep) | Anomaly score + SHAP values |
| One-Class SVM | Baseline comparison model | Anomaly score |
| Graph Neural Network (PyTorch Geometric) | Lateral-movement detection on authentication graph (nodes = hosts/accounts, edges = sessions) | Per-session lateral-movement probability |

**Metrics reported:** Precision, Recall, F1, ROC-AUC, PR-AUC — mean ± std over 5–10 randomized splits on held-out test data.

---

## Forensic Soundness

| Feature | Implementation |
|---|---|
| **Chain-of-Custody Log** | Written on every run: tool version, invoking user, timestamp, exact parameters, source files, output files |
| **Report Integrity** | SHA-256 hash of every generated HTML/PDF report, signed with `cryptography` library |
| **RFC 3161 Timestamp** | Optional (`--timestamp` flag) — submits report hash to a trusted TSA (FreeTSA by default); network dependency documented for air-gapped use |
| **Read-Only Evidence** | Syscall-level write-attempt detection and abort on source evidence files — documented as "read-only source evidence enforcement" |

> ⚠️ Digital signing and RFC 3161 timestamping provide integrity and non-repudiation evidence. They do **not** constitute legal chain-of-custody under any specific jurisdiction's evidence rules. Consult legal counsel before using in legal proceedings.

---

## Real-Time Mode

> Requires the tool to run **on the live target machine** with Administrator privileges.

```bash
python src/live/live_monitor.py --alert-email soc@example.com --smtp-server mail.example.com
```

- Uses `EventLogWatcher` (Windows API subscription) instead of polling
- Session correlator redesigned for incremental/streaming processing
- Open sessions held in memory; matched against logoff events as they arrive (configurable timeout for incomplete sessions)
- SMTP email alert dispatched on every critical-severity detection

---

## Evaluation Harness

Phase 1 establishes a ground-truth pipeline for measuring real detection performance:

1. **Labeled corpus** — Atomic Red Team attack-pattern logs + EVTX-ATTACK-SAMPLES + benign baseline logs merged into one labeled dataset
2. **Train/test split** — reproducible split script; held-out test set never touched during development
3. **Evaluation runner** — all detection modules run against held-out set; precision/recall/F1 recorded
4. **Statistical robustness** — 5–10 randomized splits; results reported as mean ± std, not single-point numbers
5. **Schema compatibility** — sample EVTXs from Windows 10, 11, Server 2016/2019/2022 parsed to confirm/fix schema differences

Scripts: `evaluation/run_evaluation.py`, `evaluation/schema_compat_test.py`

---

## Tool Benchmarking

WinLogin Forensics is benchmarked against four established tools on identical test scenarios:

| Tool | Type |
|---|---|
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | Fast EVTX triage |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | Sigma-rule EVTX analysis |
| [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) | PowerShell EVTX analysis |
| [Plaso / Log2Timeline](https://github.com/log2timeline/plaso) | Multi-source timeline |

**Compared dimensions:** Detection rate · False-positive rate · Processing speed · Deployment complexity · Report quality

Results: `benchmarking/results/`

---

## Report Structure

Auto-generated reports include:

1. **Chain-of-Custody Block** — Tool version, operator, timestamp, parameters, file hashes
2. **Case Information** — Case number, investigator name, analysis date, system metadata
3. **Executive Summary** — Key findings in plain language for non-technical stakeholders
4. **Event Statistics** — Total event count, breakdown by type, user, and logon type
5. **MITRE ATT&CK Coverage Matrix** — Which techniques were detected and with what confidence
6. **Session Analysis** — Correlated login/logoff pairs with duration and orphaned sessions
7. **Anomaly Findings** — All flagged activity with context, timestamps, severity, MITRE ID, and SHAP explanation
8. **ML Model Results** — ROC curves, AUC, precision-recall curves
9. **Full Event Table** — Complete parsed event log with all extracted fields
10. **Timeline Chart** — Embedded interactive visual timeline
11. **Integrity Block** — Report SHA-256 hash, digital signature, optional RFC 3161 timestamp
12. **Appendix** — Raw data reference, acquisition notes, evasion/limitations discussion

Export formats: **HTML** and **PDF**

---

## Project Structure

```
WinLogin-Forensics/
│
├── src/
│   ├── parsers/
│   │   ├── evtx_parser.py            # Security/System EVTX parsing; 35+ Event IDs
│   │   ├── antiforensic_detector.py  # EID 1102, 104, 4616, RecordID gaps, volume drops
│   │   ├── registry_parser.py        # SAM (RID/last-logon/creation), SOFTWARE Run keys,
│   │   │                             #   remote-access tool detection, UserAssist (NTUSER.DAT)
│   │   ├── session_correlator.py     # Logon–logoff reconstruction; streaming/incremental mode
│   │   ├── sysmon_parser.py          # Sysmon EIDs 1, 3, 11, 22; graceful fallback
│   │   └── powershell_parser.py      # PowerShell Operational EIDs 4103/4104
│   │
│   ├── analysis/
│   │   ├── anomaly_detector.py       # Rule-based detections + MITRE ID tagging
│   │   ├── feature_engineer.py       # Temporal, auth-pattern, failure, privilege, geo features
│   │   ├── ml_models.py              # IsolationForest (swept), One-Class SVM, GNN (PyG)
│   │   ├── auth_graph.py             # Authentication graph construction (nodes/edges)
│   │   ├── correlator.py             # Cross-source correlation (session<->Sysmon<->PS<->SAM<->RA tools)
│   │   └── statistics.py             # Aggregation, summary stats, alert schema
│   │
│   ├── report/
│   │   ├── html_generator.py         # Jinja2-based HTML report; ROC, SHAP, MITRE sections
│   │   ├── pdf_generator.py          # pdfkit PDF export
│   │   ├── integrity.py              # Chain-of-custody log, SHA-256 signing, RFC 3161 TSA
│   │   ├── mitre_mapper.py           # ATT&CK technique-ID lookup table + coverage matrix
│   │   └── templates/
│   │       └── report_template.html
│   │
│   ├── utils/
│   │   ├── time_utils.py             # Timezone normalization, inter-event timing
│   │   ├── safe_reader.py            # Read-only evidence enforcement, write-attempt abort
│   │   └── helpers.py
│   │
│   ├── live/
│   │   ├── live_monitor.py           # EventLogWatcher subscription-based live extraction
│   │   └── alert_dispatcher.py       # SMTP email alerting on critical-severity detections
│   │
│   ├── ui/
│   │   ├── pages/
│   │   │   ├── home.py
│   │   │   ├── event_logs.py
│   │   │   ├── registry.py
│   │   │   ├── sessions.py
│   │   │   ├── anomalies.py          # + SHAP viz, confidence score, MITRE badge
│   │   │   ├── timeline.py
│   │   │   ├── attack_matrix.py      # MITRE ATT&CK coverage matrix visualization
│   │   │   ├── realtime.py           # Live monitoring dashboard
│   │   │   ├── benchmark.py          # Benchmarking results display
│   │   │   └── report.py
│   │   └── components/
│   │       ├── sidebar.py
│   │       ├── charts.py
│   │       └── tables.py
│   │
│   └── app.py                        # Streamlit entrypoint
│
├── evaluation/
│   ├── ground_truth_methodology.md   # How events are labeled true/false positive
│   ├── run_evaluation.py             # Detection modules -> held-out test; precision/recall/F1
│   ├── schema_compat_test.py         # EVTX schema differences across Windows versions
│   └── labeled_corpus/
│       ├── README.md                 # How to acquire Atomic Red Team + EVTX-ATTACK-SAMPLES + benign
│       └── train_test_split.py       # Reproducible corpus split
│
├── benchmarking/
│   ├── README.md                     # Chainsaw / Hayabusa / DeepBlueCLI / Plaso setup
│   ├── run_all.py                    # Runs all five tools on identical scenarios; records metrics
│   └── results/
│       └── template.md
│
├── data/
│   ├── samples/                      # Anonymized test artifacts
│   └── README.md
│
├── output/
│   ├── reports/
│   └── exports/
│
├── docs/
│   ├── methodology.md                # Forensic approach, all artifact sources, analysis methodology
│   ├── user_guide.md                 # Step-by-step usage with screenshots
│   ├── event_ids.md                  # All covered Event IDs with field-level explanations
│   ├── attack_matrix.md              # MITRE ATT&CK coverage matrix (static reference)
│   ├── evasion_limitations.md        # Sub-threshold brute forcing, timestomping, selective 4104 clearing
│   ├── future_work.md                # Items explicitly out of scope for this roadmap
│   └── acquire_artifacts.md          # Registry hive acquisition guide (live + offline)
│
├── tests/
│   ├── __init__.py
│   ├── test_evtx_parser.py
│   ├── test_registry_parser.py
│   ├── test_anomaly_detector.py
│   ├── test_antiforensic_detector.py
│   ├── test_feature_engineer.py
│   ├── test_ml_models.py
│   ├── test_sysmon_parser.py
│   ├── test_powershell_parser.py
│   └── test_integrity.py
│
├── requirements.txt
├── run.bat
├── acquire_artifacts.py
├── explore_evtx.py
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
| EVTX Parsing | python-evtx, evtx, xmltodict |
| Registry Parsing | regipy, python-registry |
| Data Processing | pandas |
| Visualization | Plotly |
| Machine Learning | scikit-learn (IsolationForest, One-Class SVM, metrics) |
| Graph ML | PyTorch Geometric (GNN for lateral-movement detection) |
| Explainability | SHAP |
| Report Generation | Jinja2, pdfkit |
| Forensic Soundness | cryptography (signing), requests (RFC 3161 TSA) |
| Geolocation | geoip2 / ipinfo |
| Live Monitoring | pywin32 (EventLogWatcher), smtplib |
| Utilities | python-dateutil, colorama, networkx |

---

## Development Status

| Phase | Module | Status |
|---|---|---|
| — | Project structure & core documentation | ✅ Complete |
| **Phase 0** | EVTX parser — core events (4624, 4625, 4634, 4647) | 🔄 In Progress |
| **Phase 0** | EVTX parser — extended events (4648, 4672, 4720, 4726, 4732, 4756) | ⏳ Planned |
| **Phase 0** | EVTX parser — Kerberos events (4768, 4769, 4771, 4776) | ⏳ Planned |
| **Phase 0** | EVTX parser — persistence/system events (4698, 7045, 4616, 104) | ⏳ Planned |
| **Phase 0** | MITRE ATT&CK technique-ID mapping table | ⏳ Planned |
| **Phase 0** | Kerberos 4768/4769 aggregation/anomaly-only surfacing | ⏳ Planned |
| **Phase 1** | Ground-truth labeling methodology | ⏳ Planned |
| **Phase 1** | Atomic Red Team + EVTX-ATTACK-SAMPLES integration | ⏳ Planned |
| **Phase 1** | Labeled corpus train/test split | ⏳ Planned |
| **Phase 1** | Evaluation runner (precision/recall/F1, mean ± std) | ⏳ Planned |
| **Phase 1** | EVTX schema compatibility test (Win10/11/Server 2016–2022) | ⏳ Planned |
| **Phase 2** | Anti-forensic detector (1102, 104, 4616, RecordID gaps, volume drops) | ⏳ Planned |
| **Phase 3** | Registry parser — SAM last-logon + creation time per RID | ⏳ Planned |
| **Phase 3** | Registry parser — SOFTWARE Run keys + remote-access tool detection | ⏳ Planned |
| **Phase 3** | Registry parser — UserAssist from NTUSER.DAT | ⏳ Planned |
| **Phase 3** | Registry hive acquisition (live RegSaveKeyEx + offline) | ⏳ Planned |
| **Phase 4** | Sysmon parser (EIDs 1, 3, 11, 22) | ⏳ Planned |
| **Phase 4** | PowerShell Operational parser (EIDs 4103, 4104) | ⏳ Planned |
| **Phase 4** | Sysmon <-> session correlation | ⏳ Planned |
| **Phase 4** | PowerShell 4104 <-> flagged session correlation | ⏳ Planned |
| **Phase 5** | Feature engineering (temporal, auth-pattern, failure, privilege, geo) | ⏳ Planned |
| **Phase 5** | IsolationForest hyperparameter sweep | ⏳ Planned |
| **Phase 5** | One-Class SVM baseline | ⏳ Planned |
| **Phase 5** | Authentication graph construction | ⏳ Planned |
| **Phase 5** | GNN lateral-movement detection | ⏳ Planned |
| **Phase 5** | SHAP explainability output | ⏳ Planned |
| **Phase 5** | ROC/AUC/PR curve computation | ⏳ Planned |
| **Phase 6** | Chain-of-custody logging | ⏳ Planned |
| **Phase 6** | Report digital signing (SHA-256 + cryptography) | ⏳ Planned |
| **Phase 6** | RFC 3161 trusted-timestamp (optional flag) | ⏳ Planned |
| **Phase 6** | Read-only evidence enforcement | ⏳ Planned |
| **Phase 7** | EventLogWatcher live extraction | ⏳ Planned |
| **Phase 7** | Incremental session correlator | ⏳ Planned |
| **Phase 7** | SMTP email alerting | ⏳ Planned |
| **Phase 8** | Benchmarking harness (Chainsaw, Hayabusa, DeepBlueCLI, Plaso) | ⏳ Planned |
| **Phase 9** | MITRE ATT&CK matrix visualization | ⏳ Planned |
| **Phase 9** | Evasion/limitations documentation | ⏳ Planned |
| **Phase 9** | Reproducibility (evaluation scripts published) | ⏳ Planned |

---

## Documentation

| Document | Description |
|---|---|
| [Methodology](docs/methodology.md) | Forensic approach, all artifact sources, and analysis methodology |
| [User Guide](docs/user_guide.md) | Step-by-step usage instructions with screenshots |
| [Event ID Reference](docs/event_ids.md) | All covered Event IDs with field-level explanations |
| [MITRE ATT&CK Matrix](docs/attack_matrix.md) | Coverage matrix — which techniques are detected and how |
| [Evasion & Limitations](docs/evasion_limitations.md) | Honest scope limitations and known evasion scenarios |
| [Future Work](docs/future_work.md) | Features explicitly deferred from this roadmap |
| [Sample Data Guide](data/README.md) | How to safely acquire test artifacts from a Windows system |
| [Artifact Acquisition](docs/acquire_artifacts.md) | Live and offline registry hive acquisition guide |
| [Ground Truth Methodology](evaluation/ground_truth_methodology.md) | How events are labeled true/false positive for evaluation |

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
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) by Red Canary — adversary simulation framework
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by Samir Bousseaden — labeled attack EVTX samples
- [PyTorch Geometric](https://pytorch-geometric.readthedocs.io/) — GNN framework
- [SHAP](https://shap.readthedocs.io/) — ML explainability library
- Windows Security Log Encyclopedia — [ultimatewindowssecurity.com](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- MITRE ATT&CK Framework — [attack.mitre.org](https://attack.mitre.org)

---

## Author

**Ashish Kumar**  
[github.com/Ashiii27](https://github.com/Ashiii27) · [linkedin.com/in/ashiii27](https://linkedin.com/in/ashiii27)

---

## License

Released under the [MIT License](LICENSE).  
© 2026 Ashish Kumar
