"""
WinLogin Forensics - MITRE ATT&CK Mapper
=====================================================
Technique-ID lookup table and coverage-matrix generation for forensic reports.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set


# tactic -> list of techniques relevant to WinLogin Forensics
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
        "detection": "After-Hours Login / Impossible Travel",
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
        "detection": "Log Volume Drop / SAM Record Mismatch",
        "severity": "Medium",
    },
}

# Map detection rule names (from anomaly dict "anomaly" field) to MITRE IDs
DETECTION_TO_MITRE: Dict[str, str] = {
    "Brute Force Attack": "T1110.001",
    "Credential Stuffing": "T1110.004",
    "Pass-the-Hash / Explicit Credential": "T1550.002",
    "Pass-the-Hash": "T1550.002",
    "Explicit Credential": "T1550.002",
    "Kerberoasting": "T1558.003",
    "Kerberos Burst": "T1558",
    "AS-REP Roasting": "T1558.004",
    "Admin Privilege Escalation": "T1078.002",
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
    "Log Clearing": "T1070.001",
    "Timestamp Manipulation": "T1070.006",
    "Selective Record Deletion": "T1070.001",
    "Log Volume Drop": "T1070",
    "SAM Record Mismatch": "T1070",
}


def lookup_technique(mitre_id: str) -> Optional[Dict[str, Any]]:
    """Return technique metadata for a MITRE ATT&CK ID, or None if unknown."""
    return MITRE_TECHNIQUES.get(mitre_id)


def resolve_mitre_id(anomaly: Dict[str, Any]) -> str:
    """
    Resolve a MITRE technique ID from an anomaly finding dict.
    Uses explicit mitre_id if present, otherwise maps from the anomaly name.
    """
    explicit = str(anomaly.get("mitre_id", "")).strip()
    if explicit and explicit in MITRE_TECHNIQUES:
        return explicit
    if explicit:
        return explicit

    name = str(anomaly.get("anomaly", "")).strip()
    return DETECTION_TO_MITRE.get(name, "T0000")


def build_coverage_matrix(anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build a MITRE ATT&CK coverage matrix from anomaly findings.

    Returns a list of rows with keys:
        mitre_id, name, tactic, detection, severity, detected, count,
        max_confidence, sample_details
    """
    detected: Dict[str, Dict[str, Any]] = {}

    for finding in anomalies:
        mitre_id = resolve_mitre_id(finding)
        meta = lookup_technique(mitre_id) or {
            "name": finding.get("anomaly", "Unknown"),
            "tactic": "Unknown",
            "detection": finding.get("anomaly", "Unknown"),
            "severity": finding.get("severity", "Unknown"),
        }
        confidence = float(finding.get("confidence", 0.0) or 0.0)

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
            row["sample_details"] = str(finding.get("details", ""))[:200]

    matrix: List[Dict[str, Any]] = []
    for mitre_id, meta in MITRE_TECHNIQUES.items():
        if mitre_id in detected:
            matrix.append(detected[mitre_id])
        else:
            matrix.append({
                "mitre_id": mitre_id,
                "name": meta["name"],
                "tactic": meta["tactic"],
                "detection": meta["detection"],
                "severity": meta["severity"],
                "detected": False,
                "count": 0,
                "max_confidence": 0.0,
                "sample_details": "",
            })

    # Include ad-hoc detections not in the static table
    for mitre_id, row in detected.items():
        if mitre_id not in MITRE_TECHNIQUES:
            matrix.append(row)

    matrix.sort(key=lambda r: (not r["detected"], r["tactic"], r["mitre_id"]))
    return matrix


def coverage_summary(anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return high-level MITRE coverage statistics."""
    matrix = build_coverage_matrix(anomalies)
    detected_ids: Set[str] = {r["mitre_id"] for r in matrix if r["detected"]}
    total_techniques = len(MITRE_TECHNIQUES)
    return {
        "total_techniques_tracked": total_techniques,
        "techniques_detected": len(detected_ids),
        "coverage_percent": round(len(detected_ids) / total_techniques * 100, 1) if total_techniques else 0.0,
        "detected_ids": sorted(detected_ids),
    }
