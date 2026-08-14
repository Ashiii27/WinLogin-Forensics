"""
WinLogin Forensics - Alert dispatcher
=====================================
Sends SMTP email when a live finding is HIGH or CRITICAL. Configuration
is loaded from ``config/alert_config.yaml`` (never hardcoded).
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import yaml


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "alert_config.yaml"


def load_alert_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load alert configuration from YAML.

    Parameters
    ----------
    path : Path, optional
        Config file. Defaults to ``config/alert_config.yaml``.

    Returns
    -------
    dict
        Parsed configuration.
    """
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not cfg_path.exists():
        return {
            "smtp": {
                "host": "localhost",
                "port": 25,
                "use_tls": False,
                "from_address": "winlogin-forensics@localhost",
                "to_addresses": ["soc@localhost"],
            },
            "thresholds": {"score": 0.75, "severities": ["HIGH", "CRITICAL"]},
        }
    with open(cfg_path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


class AlertDispatcher:
    """
    Dispatch SMTP alerts for high-severity live detections.

    Parameters
    ----------
    config : dict, optional
        Pre-loaded config. Loaded from disk when omitted.
    config_path : Path, optional
        Alternate YAML path.
    smtp_client : Any, optional
        Injected client (must implement ``send_message``). Used by tests.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: Optional[Path] = None,
        smtp_client: Any = None,
    ):
        self.config = config or load_alert_config(config_path)
        self.smtp_client = smtp_client
        self.sent: List[EmailMessage] = []

    def should_alert(self, finding: Dict[str, Any]) -> bool:
        """
        Return True when the finding crosses the configured threshold.

        Parameters
        ----------
        finding : dict
            Live finding with ``severity`` and/or ``score``.

        Returns
        -------
        bool
        """
        thresholds = self.config.get("thresholds") or {}
        severities = {str(s).upper() for s in thresholds.get("severities", ["HIGH", "CRITICAL"])}
        sev = str(finding.get("severity", "")).upper()
        if sev in severities:
            return True
        try:
            score = float(finding.get("score", finding.get("ensemble_score", 0)) or 0)
        except (TypeError, ValueError):
            score = 0.0
        return score >= float(thresholds.get("score", 0.75))

    def format_body(self, finding: Dict[str, Any]) -> str:
        """
        Build the email body.

        Parameters
        ----------
        finding : dict
            Finding record.

        Returns
        -------
        str
            Plain-text body.
        """
        shap = finding.get("shap_explanation") or finding.get("shap") or {}
        top3 = []
        if isinstance(shap, dict):
            ranked = sorted(shap.items(), key=lambda kv: abs(float(kv[1] or 0)), reverse=True)
            top3 = [f"{k}={v}" for k, v in ranked[:3]]
        lines = [
            "WinLogin Forensics — live alert",
            f"Anomaly type : {finding.get('anomaly') or finding.get('detection_type')}",
            f"Severity     : {finding.get('severity')}",
            f"MITRE        : {finding.get('mitre_id')}",
            f"User         : {finding.get('user') or finding.get('Username') or finding.get('TargetUserName')}",
            f"Workstation  : {finding.get('workstation') or finding.get('WorkstationName')}",
            f"Timestamp    : {finding.get('timestamp')}",
            f"Score        : {finding.get('score', finding.get('ensemble_score', ''))}",
            f"Top SHAP     : {', '.join(top3) if top3 else 'n/a'}",
            "",
            str(finding.get("details") or finding.get("evidence_detail") or ""),
        ]
        return "\n".join(lines)

    def dispatch(self, finding: Dict[str, Any]) -> Optional[EmailMessage]:
        """
        Send one alert if the finding meets the threshold.

        Parameters
        ----------
        finding : dict
            Live finding.

        Returns
        -------
        Optional[EmailMessage]
            The message that was handed to SMTP, or None if suppressed.
        """
        if not self.should_alert(finding):
            return None
        smtp_cfg = self.config.get("smtp") or {}
        msg = EmailMessage()
        msg["Subject"] = (
            f"[WinLogin] {finding.get('severity', 'ALERT')} "
            f"{finding.get('anomaly') or finding.get('detection_type')} "
            f"({finding.get('mitre_id', '')})"
        )
        msg["From"] = smtp_cfg.get("from_address", "winlogin-forensics@localhost")
        to_addr = smtp_cfg.get("to_addresses") or ["soc@localhost"]
        if isinstance(to_addr, str):
            to_addr = [to_addr]
        msg["To"] = ", ".join(to_addr)
        msg.set_content(self.format_body(finding))
        self.sent.append(msg)
        self._send(msg, smtp_cfg)
        return msg

    def dispatch_many(self, findings: Iterable[Dict[str, Any]]) -> List[EmailMessage]:
        """Dispatch every qualifying finding. Returns sent messages."""
        sent = []
        for finding in findings:
            msg = self.dispatch(finding)
            if msg is not None:
                sent.append(msg)
        return sent

    def _send(self, msg: EmailMessage, smtp_cfg: Dict[str, Any]) -> None:
        client = self.smtp_client
        if client is not None:
            if hasattr(client, "send_message"):
                client.send_message(msg)
            elif hasattr(client, "sendmail"):
                client.sendmail(msg["From"], msg["To"].split(","), msg.as_string())
            return
        host = smtp_cfg.get("host", "localhost")
        port = int(smtp_cfg.get("port", 25))
        try:
            with smtplib.SMTP(host, port, timeout=10) as smtp:
                if smtp_cfg.get("use_tls"):
                    smtp.starttls()
                user, password = smtp_cfg.get("username"), smtp_cfg.get("password")
                if user:
                    smtp.login(str(user), str(password or ""))
                smtp.send_message(msg)
        except OSError:
            # Offline / no relay — the message is still recorded on ``self.sent``
            return
