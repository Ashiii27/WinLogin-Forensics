# Methodology

WinLogin Forensics follows a four-layer architecture that is fixed by
the project contract:

1. **Input sources** — offline `.evtx` files and registry hives. Live
   acquisition goes through `acquire_artifacts.py` (VSS or `reg.exe`)
   and records SHA-256 immediately.
2. **Parsing layer** — EVTX, Sysmon, PowerShell, SAM / SOFTWARE /
   NTUSER, plus the anti-forensic detector. Evidence is opened
   `O_RDONLY`; a write attempt or hash change aborts analysis.
3. **Analysis engine** — session correlation on `TargetLogonId`,
   rule-based detections, feature engineering (including impossible
   travel), IsolationForest + One-Class SVM ensemble with SHAP, and a
   bipartite GCN over the user↔workstation graph.
4. **Presentation** — Streamlit UI, CLI, and signed HTML/PDF reports
   with a chain-of-custody log that is the first thing initialised and
   the last thing written.

Ground-truth evaluation lives in `evaluation/`. Peer-tool comparison
lives in `benchmarking/`.
