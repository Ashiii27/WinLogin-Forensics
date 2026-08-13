"""
WinLogin Forensics - MITRE ATT&CK Mapper
========================================
Technique-ID lookup table (implementation-plan contract + extended coverage)
and coverage-matrix generation for forensic reports.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Contract table from the implementation plan (Event / Rule → Technique)
# ---------------------------------------------------------------------------
MITRE_EVENT_RULES: Dict[str, Dict[str, str]] = {
    "Repeated 4625": {
        "technique_id": "T1110.001",
        "name": "Brute Force: Password Guessing",
    },
    "Pass-the-Hash pattern": {
        "technique_id": "T1550.002",
        "name": "Use Alternate Auth Material",
    },
    "Kerberoasting (4769)": {
        "technique_id": "T1558.003",
        "name": "Steal or Forge Kerberos Tickets",
    },
    "Orphaned privileged session": {
        "technique_id": "T1078",
        "name": "Valid Accounts",
    },
    "Log clearing (1102, 104)": {
        "technique_id": "T1070",
        "name": "Indicator Removal",
    },
}

# Aliases so lookups are forgiving about wording
_RULE_ALIASES: Dict[str, str] = {
    "repeated 4625": "Repeated 4625",
    "brute force": "Repeated 4625",
    "brute force attack": "Repeated 4625",
    "brute force: password guessing": "Repeated 4625",
    "t1110.001": "Repeated 4625",
    "pass-the-hash pattern": "Pass-the-Hash pattern",
    "pass-the-hash": "Pass-the-Hash pattern",
    "pass the hash": "Pass-the-Hash pattern",
    "pth": "Pass-the-Hash pattern",
    "use alternate auth material": "Pass-the-Hash pattern",
    "t1550.002": "Pass-the-Hash pattern",
    "kerberoasting (4769)": "Kerberoasting (4769)",
    "kerberoasting": "Kerberoasting (4769)",
    "steal or forge kerberos tickets": "Kerberoasting (4769)",
    "t1558.003": "Kerberoasting (4769)",
    "orphaned privileged session": "Orphaned privileged session",
    "orphaned session": "Orphaned privileged session",
    "valid accounts": "Orphaned privileged session",
    "t1078": "Orphaned privileged session",
    "log clearing (1102, 104)": "Log clearing (1102, 104)",
    "log clearing": "Log clearing (1102, 104)",
    "indicator removal": "Log clearing (1102, 104)",
    "t1070": "Log clearing (1102, 104)",
    "1102": "Log clearing (1102, 104)",
    "104": "Log clearing (1102, 104)",
}


# Extended technique catalogue used by reports / UI
MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "detection": "Brute Force Attack",
        "severity": "High",
    },
    "T1110.004": {
        "name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "detection": "Credential Stuffing",
        "severity": "High",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "detection": "Account Lockout / Repeated Unlock Attempts",
        "severity": "Medium",
    },
    "T1550.002": {
        "name": "Use Alternate Authentication Material: Pass the Hash",
        "tactic": "Lateral Movement",
        "detection": "Pass-the-Hash / Explicit Credential",
        "severity": "High",
    },
    "T1558.003": {
        "name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "tactic": "Credential Access",
        "detection": "Kerberoasting",
        "severity": "High",
    },
    "T1558.004": {
        "name": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
        "tactic": "Credential Access",
        "detection": "AS-REP Roasting",
        "severity": "Medium",
    },
    "T1558": {
        "name": "Steal or Forge Kerberos Tickets",
        "tactic": "Credential Access",
        "detection": "Kerberos Burst",
        "severity": "Medium",
    },
    "T1078.002": {
        "name": "Valid Accounts: Domain Accounts",
        "tactic": "Defense Evasion",
        "detection": "Admin Privilege Escalation",
        "severity": "High",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "detection": "After-Hours Login / Impossible Travel / Orphaned Privileged Session",
        "severity": "Medium",
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "detection": "Lateral Movement",
        "severity": "High",
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "detection": "RDP from Unknown Source",
        "severity": "Medium",
    },
    "T1136.001": {
        "name": "Create Account: Local Account",
        "tactic": "Persistence",
        "detection": "New Account Created",
        "severity": "High",
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "detection": "Mass Account Modification",
        "severity": "High",
    },
    "T1098.007": {
        "name": "Account Manipulation: Additional Local or Domain Groups",
        "tactic": "Persistence",
        "detection": "Group Membership Change",
        "severity": "Medium",
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "detection": "Scheduled Task Created",
        "severity": "Medium",
    },
    "T1543.003": {
        "name": "Create or Modify System Process: Windows Service",
        "tactic": "Persistence",
        "detection": "New Service Installed",
        "severity": "Medium",
    },
    "T1070.001": {
        "name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "detection": "Log Clearing / Selective Record Deletion",
        "severity": "High",
    },
    "T1070.006": {
        "name": "Indicator Removal: Timestomp",
        "tactic": "Defense Evasion",
        "detection": "Timestamp Manipulation",
        "severity": "High",
    },
    "T1070": {
        "name": "Indicator Removal on Host",
        "tactic": "Defense Evasion",
        "detection": "Log Volume Drop / SAM Record Mismatch / Log Clearing",
        "severity": "Medium",
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "detection": "Obfuscated PowerShell",
        "severity": "High",
    },
}


DETECTION_TO_MITRE: Dict[str, str] = {
    "Brute Force Attack": "T1110.001",
    "Repeated 4625": "T1110.001",
    "Credential Stuffing": "T1110.004",
    "Pass-the-Hash / Explicit Credential": "T1550.002",
    "Pass-the-Hash": "T1550.002",
    "Pass-the-Hash pattern": "T1550.002",
    "Explicit Credential": "T1550.002",
    "Kerberoasting": "T1558.003",
    "Kerberoasting (4769)": "T1558.003",
    "Kerberos Burst": "T1558",
    "AS-REP Roasting": "T1558.004",
    "Admin Privilege Escalation": "T1078.002",
    "Orphaned privileged session": "T1078",
    "Lateral Movement": "T1021",
    "New Account Created": "T1136.001",
    "Mass Account Modification": "T1098",
    "Group Membership Change": "T1098.007",
    "Scheduled Task Created": "T1053.005",
    "New Service Installed": "T1543.003",
    "After-Hours Login": "T1078",
    "Account Lockout": "T1110",
    "RDP from Unknown Source": "T1021.001",
    "Repeated Unlock Attempts": "T1110",
    "Impossible Travel": "T1078",
    "Log Clearing": "T1070",
    "Log clearing (1102, 104)": "T1070",
    "Timestamp Manipulation": "T1070.006",
    "Selective Record Deletion": "T1070.001",
    "Log Volume Drop": "T1070",
    "SAM Record Mismatch": "T1070",
    "Obfuscated PowerShell": "T1059.001",
    "RecordID Gap": "T1070.001",
}


def lookup_technique(mitre_id: str) -> Optional[Dict[str, Any]]:
    """
    Return technique metadata for a MITRE ATT&CK ID.

    Parameters
    ----------
    mitre_id : str
        Technique ID such as ``T1110.001``.

    Returns
    -------
    Optional[Dict[str, Any]]
        Catalogue row, or None if unknown.
    """
    return MITRE_TECHNIQUES.get(str(mitre_id).strip())


def lookup_technique_id(rule: str) -> str:
    """
    Return the MITRE technique ID for an event/rule name.

    This is the contract lookup used by Phase 0 tests.

    Parameters
    ----------
    rule : str
        Detection rule or event description (e.g. ``"Repeated 4625"``).

    Returns
    -------
    str
        Technique ID such as ``T1110.001``. Empty string if unknown.
    """
    if rule is None:
        return ""
    text = str(rule).strip()
    if text in MITRE_EVENT_RULES:
        return MITRE_EVENT_RULES[text]["technique_id"]
    alias = _RULE_ALIASES.get(text.lower())
    if alias and alias in MITRE_EVENT_RULES:
        return MITRE_EVENT_RULES[alias]["technique_id"]
    if text in DETECTION_TO_MITRE:
        return DETECTION_TO_MITRE[text]
    if text in MITRE_TECHNIQUES:
        return text
    return ""


def lookup_rule(rule: str) -> Optional[Dict[str, str]]:
    """
    Return ``{technique_id, name}`` for a contract rule.

    Parameters
    ----------
    rule : str
        Rule name from the implementation-plan table.

    Returns
    -------
    Optional[Dict[str, str]]
        Mapping row or None.
    """
    tid = lookup_technique_id(rule)
    if not tid:
        return None
    # Prefer the contract row
    key = rule if rule in MITRE_EVENT_RULES else _RULE_ALIASES.get(str(rule).lower())
    if key and key in MITRE_EVENT_RULES:
        return dict(MITRE_EVENT_RULES[key])
    meta = lookup_technique(tid) or {}
    return {"technique_id": tid, "name": meta.get("name", "")}


def resolve_mitre_id(anomaly: Dict[str, Any]) -> str:
    """
    Resolve a MITRE technique ID from an anomaly finding dict.

    Parameters
    ----------
    anomaly : dict
        Finding with optional ``mitre_id`` / ``anomaly`` / ``detection_type``.

    Returns
    -------
    str
        Technique ID, or ``T0000`` if unresolved.
    """
    explicit = str(anomaly.get("mitre_id", "")).strip()
    if explicit and explicit in MITRE_TECHNIQUES:
        return explicit
    if explicit.startswith("T") and len(explicit) >= 5:
        return explicit

    for key in ("anomaly", "detection_type", "rule", "name"):
        name = str(anomaly.get(key, "")).strip()
        if not name:
            continue
        mapped = lookup_technique_id(name)
        if mapped:
            return mapped
        if name in DETECTION_TO_MITRE:
            return DETECTION_TO_MITRE[name]
    return "T0000"


def map_event(event_id: int, context: Optional[Dict[str, Any]] = None) -> List[Tuple[str, str]]:
    """
    Map a raw Event ID (+ optional context) onto MITRE techniques.

    Parameters
    ----------
    event_id : int
        Windows Event ID.
    context : dict, optional
        Extra signals (e.g. ``ticket_encryption``, ``failed_count``).

    Returns
    -------
    List[Tuple[str, str]]
        ``(technique_id, name)`` pairs.
    """
    ctx = context or {}
    hits: List[Tuple[str, str]] = []
    if event_id == 4625 and int(ctx.get("failed_count", 1) or 1) >= 5:
        hits.append(("T1110.001", "Brute Force: Password Guessing"))
    if event_id in (4648,) or ctx.get("pass_the_hash"):
        hits.append(("T1550.002", "Use Alternate Auth Material"))
    if event_id == 4769:
        enc = str(ctx.get("ticket_encryption", "")).lower()
        if enc in {"0x17", "17", "rc4", "0x0017"}:
            hits.append(("T1558.003", "Steal or Forge Kerberos Tickets"))
    if event_id in (1102, 104):
        hits.append(("T1070", "Indicator Removal"))
    if event_id == 4616:
        hits.append(("T1070.006", "Indicator Removal: Timestomp"))
    if ctx.get("orphaned_privileged"):
        hits.append(("T1078", "Valid Accounts"))
    return hits


def build_coverage_matrix(anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build a MITRE ATT&CK coverage matrix from anomaly findings.

    Parameters
    ----------
    anomalies : list of dict
        Detector output records.

    Returns
    -------
    List[Dict[str, Any]]
        Rows with ``mitre_id, name, tactic, detection, severity, detected,
        count, max_confidence, sample_details``.
    """
    detected: Dict[str, Dict[str, Any]] = {}

    for finding in anomalies or []:
        mitre_id = resolve_mitre_id(finding)
        meta = lookup_technique(mitre_id) or {
            "name": finding.get("anomaly") or finding.get("detection_type") or "Unknown",
            "tactic": "Unknown",
            "detection": finding.get("anomaly") or finding.get("detection_type") or "Unknown",
            "severity": finding.get("severity", "Unknown"),
        }
        try:
            confidence = float(finding.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0

        if mitre_id not in detected:
            detected[mitre_id] = {
                "mitre_id": mitre_id,
                "name": meta["name"],
                "tactic": meta["tactic"],
                "detection": meta["detection"],
                "severity": meta["severity"],
                "detected": True,
                "count": 0,
                "max_confidence": 0.0,
                "sample_details": "",
            }
        row = detected[mitre_id]
        row["count"] += 1
        row["max_confidence"] = max(row["max_confidence"], confidence)
        if not row["sample_details"]:
            detail = finding.get("details") or finding.get("evidence_detail") or ""
            row["sample_details"] = str(detail)[:200]

    matrix: List[Dict[str, Any]] = []
    for mitre_id, meta in MITRE_TECHNIQUES.items():
        if mitre_id in detected:
            matrix.append(detected[mitre_id])
        else:
            matrix.append(
                {
                    "mitre_id": mitre_id,
                    "name": meta["name"],
                    "tactic": meta["tactic"],
                    "detection": meta["detection"],
                    "severity": meta["severity"],
                    "detected": False,
                    "count": 0,
                    "max_confidence": 0.0,
                    "sample_details": "",
                }
            )
    for mitre_id, row in detected.items():
        if mitre_id not in MITRE_TECHNIQUES:
            matrix.append(row)
    matrix.sort(key=lambda r: (not r["detected"], r["tactic"], r["mitre_id"]))
    return matrix


def coverage_summary(anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Return high-level MITRE coverage statistics.

    Parameters
    ----------
    anomalies : list of dict
        Detector output records.

    Returns
    -------
    Dict[str, Any]
        ``total_techniques_tracked``, ``techniques_detected``,
        ``coverage_percent``, ``detected_ids``.
    """
    matrix = build_coverage_matrix(anomalies)
    detected_ids: Set[str] = {r["mitre_id"] for r in matrix if r["detected"] and r["mitre_id"] != "T0000"}
    total_techniques = len(MITRE_TECHNIQUES)
    return {
        "total_techniques_tracked": total_techniques,
        "techniques_detected": len(detected_ids),
        "coverage_percent": round(len(detected_ids) / total_techniques * 100, 1) if total_techniques else 0.0,
        "detected_ids": sorted(detected_ids),
    }
