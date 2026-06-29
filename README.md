<div align="center">

# 🔍 WinLogin Forensics

### A Comprehensive Windows Login Artifact Extraction and Analysis Framework

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.37.0-red?style=for-the-badge&logo=streamlit)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=for-the-badge)]()

> A digital forensics tool designed to extract, correlate, analyze, and visualize 
> Windows login artifacts from Event Logs and Registry hives — helping investigators 
> reconstruct authentication timelines and detect suspicious activity.

---

[Features](#-features) • 
[Architecture](#-architecture) • 
[Installation](#-installation) • 
[Usage](#-usage) • 
[Documentation](#-documentation) • 
[Screenshots](#-screenshots)

</div>

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Why WinLogin Forensics?](#-why-winlogin-forensics)
- [Features](#-features)
- [Covered Event IDs](#-covered-event-ids)
- [Logon Types](#-logon-types)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Tech Stack](#-tech-stack)
- [Installation](#-installation)
- [Usage](#-usage)
- [Pages and Modules](#-pages-and-modules)
- [Anomaly Detection](#-anomaly-detection)
- [Report Generation](#-report-generation)
- [Sample Data](#-sample-data)
- [Documentation](#-documentation)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Author](#-author)
- [License](#-license)

---

## 🧭 Overview

**WinLogin Forensics** is a Python-based digital forensics framework built for 
analyzing Windows authentication activity. It is designed to assist forensic 
investigators, security analysts, and researchers in understanding **who logged in, 
when, from where, how, and whether anything suspicious occurred** — all from 
Windows Event Logs and Registry hives.

Windows operating systems maintain detailed records of every login attempt, 
session creation, privilege assignment, and account modification through its 
**Security Event Log** (`Security.evtx`) and **Registry hives** (SAM, SYSTEM, 
SECURITY). However, these artifacts are stored in binary formats that are 
difficult to read and interpret manually.

**WinLogin Forensics** solves this by:
- Parsing raw `.evtx` and Registry hive files
- Correlating related events into meaningful sessions
- Classifying login behavior by type and context
- Detecting anomalies and suspicious patterns
- Presenting everything in a clean, interactive web interface
- Generating professional forensic reports for documentation

---

## ❓ Why WinLogin Forensics?

Existing tools like **Windows Event Viewer**, **Autopsy**, and **Event Log Explorer** 
either:
- Require expensive licenses
- Are too complex for focused login analysis
- Don't provide automated anomaly detection
- Don't correlate login and logoff events into sessions
- Don't generate structured forensic reports

**WinLogin Forensics** is purpose-built for login artifact analysis with a clean, 
accessible web interface — making it suitable for both professional investigators 
and students learning digital forensics.

| Feature | Event Viewer | Autopsy | WinLogin Forensics |
|---------|-------------|---------|-------------------|
| Free & Open Source | ✅ | ✅ | ✅ |
| Login-focused Analysis | ❌ | ❌ | ✅ |
| Session Correlation | ❌ | ❌ | ✅ |
| Anomaly Detection | ❌ | ❌ | ✅ |
| Registry Analysis | ❌ | ✅ | ✅ |
| Interactive Web UI | ❌ | ❌ | ✅ |
| Forensic Report Generation | ❌ | ✅ | ✅ |
| Logon Type Classification | ❌ | ❌ | ✅ |

---

## ✨ Features

### 🗂️ Event Log Parsing
- Parses Windows Security Event Log (`.evtx`) files
- Extracts all login-related events with full field detail
- Supports filtering by Event ID, username, date range, logon type, and IP address
- Handles large log files efficiently
- Timezone-aware timestamp normalization

### 🔗 Session Correlation
- Links **logon events** (4624) with **logoff events** (4634/4647) using `TargetLogonId`
- Calculates session duration for each login session
- Identifies orphaned sessions (login with no corresponding logoff)
- Provides per-user session history

### 🧭 Logon Type Analysis
- Classifies every login event by its **Logon Type** (see table below)
- Provides statistics and breakdowns by logon type
- Highlights unusual logon types for specific accounts

### 🗄️ Registry Forensics
- Parses offline Registry hive files:
  - **SAM hive** — User accounts, last login time, bad password count, 
    account status
  - **SYSTEM hive** — Computer name, timezone, last shutdown time
  - **SECURITY hive** — Cached domain credentials, security policies
- No live system access required — works on acquired hive files

### 🚨 Anomaly Detection
- **Brute Force Detection** — Multiple failed logins (4625) in a short timeframe
- **After-Hours Login Detection** — Logins outside business hours
- **Admin Privilege Escalation** — Special privileges assigned at login (4672)
- **Lateral Movement Detection** — Explicit credential usage (4648)
- **Account Lockout Detection** — Accounts locked due to repeated failures (4740)
- **RDP Anomaly Detection** — Unusual Remote Desktop login patterns (4778/4779)
- **New Account Creation** — User accounts created during investigation period (4720)
- **Off-hours Admin Activity** — Admin accounts active at suspicious times

### 📈 Timeline Visualization
- Interactive login activity timeline using Plotly
- Filter by user, event type, date range, and logon type
- Zoom in/out on specific time periods
- Color-coded events for quick visual analysis

### 📑 Report Generation
- Auto-generated **HTML forensic report** with full findings
- **PDF export** for submission and documentation
- Includes:
  - Executive summary
  - Event statistics
  - Session analysis
  - Anomaly findings
  - Full event tables
  - Timeline charts

### 🌐 Web Interface
- Clean, multi-page Streamlit dashboard
- File upload for `.evtx` and Registry hive files
- Real-time analysis and visualization
- No command-line knowledge required

---

## 🔖 Covered Event IDs

| Event ID | Description | Category |
|----------|-------------|----------|
| 4624 | Successful logon | Authentication |
| 4625 | Failed logon attempt | Authentication |
| 4634 | Account logoff | Session |
| 4647 | User-initiated logoff | Session |
| 4648 | Logon with explicit credentials | Suspicious |
| 4672 | Special privileges assigned to logon | Privilege |
| 4720 | User account created | Account |
| 4722 | User account enabled | Account |
| 4723 | Password change attempt | Account |
| 4724 | Password reset attempt | Account |
| 4725 | User account disabled | Account |
| 4726 | User account deleted | Account |
| 4728 | Member added to security-enabled global group | Account |
| 4732 | Member added to security-enabled local group | Account |
| 4740 | User account locked out | Account |
| 4767 | User account unlocked | Account |
| 4778 | Remote Desktop session reconnected | RDP |
| 4779 | Remote Desktop session disconnected | RDP |
| 4800 | Workstation locked | Session |
| 4801 | Workstation unlocked | Session |

---

## 🧩 Logon Types

| Type | Name | Description |
|------|------|-------------|
| 2 | Interactive | Direct keyboard login at the machine |
| 3 | Network | Login over network (file shares, etc.) |
| 4 | Batch | Scheduled task or batch job login |
| 5 | Service | Windows service login |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Network login with plaintext credentials |
| 9 | NewCredentials | RunAs with different credentials |
| 10 | RemoteInteractive | Remote Desktop Protocol (RDP) login |
| 11 | CachedInteractive | Login using cached domain credentials |
| 12 | CachedRemoteInteractive | Cached RDP login |
| 13 | CachedUnlock | Workstation unlock using cached credentials |

---

## 🏗️ Architecture
