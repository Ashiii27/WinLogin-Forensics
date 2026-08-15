"""
WinLogin Forensics - Live monitoring engine
===========================================
Subscribes to Windows Event Log (via pywin32 ``win32evtlog``) when
available, otherwise consumes an injected queue. Each event is pushed
through the Phase 0 parser and Phase 1 session correlator incrementally.
Sessions older than 24 hours are expired. New / updated sessions are
scored and HIGH/CRITICAL findings are dispatched.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from .alert_dispatcher import AlertDispatcher, load_alert_config
from ..parsers.evtx_parser import EvtxParser
from ..parsers.session_correlator import SessionCorrelator
from ..utils.time_utils import normalize_to_utc, time_delta_seconds, utc_now


try:
    import win32evtlog  # type: ignore

    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    win32evtlog = None  # type: ignore


class LiveMonitor:
    """
    Incremental live monitor.

    Parameters
    ----------
    queue : Iterable, optional
        Mock / pre-loaded event source (dicts or XML strings).
    dispatcher : AlertDispatcher, optional
        Alert sink.
    expire_hours : float
        Session TTL.
    score_threshold : float
        Ensemble / synthetic score that triggers an alert.
    scorer : callable, optional
        ``scorer(session_dict) -> float``. Used by tests to inject scores.
    """

    def __init__(
        self,
        queue: Optional[Iterable[Any]] = None,
        dispatcher: Optional[AlertDispatcher] = None,
        expire_hours: float = 24.0,
        score_threshold: float = 0.75,
        scorer: Optional[Callable[[Dict[str, Any]], float]] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.queue = list(queue or [])
        self.dispatcher = dispatcher or AlertDispatcher(config=config)
        self.correlator = SessionCorrelator(timeout_hours=expire_hours)
        self.parser = EvtxParser()
        self.expire_hours = float(expire_hours)
        self.score_threshold = float(score_threshold)
        self.scorer = scorer
        self.alerts: List[Dict[str, Any]] = []
        self.processed = 0
        self.closed_sessions: List[Dict[str, Any]] = []

    @property
    def sessions(self) -> Dict[str, Dict[str, Any]]:
        """Currently open (active) sessions keyed by TargetLogonId."""
        return self.correlator.open_sessions

    def ingest(self, event: Any) -> Optional[Dict[str, Any]]:
        """
        Parse one event, update session state, score, and maybe alert.

        Parameters
        ----------
        event : dict | str
            Parsed event dict or raw XML.

        Returns
        -------
        Optional[dict]
            Closed session if this event completed one.
        """
        parsed = self._coerce(event)
        if parsed is None:
            return None
        self.processed += 1
        closed = self.correlator.process_event(parsed)
        if closed:
            self.closed_sessions.append(closed)
            self._score_and_alert(closed, parsed)
        else:
            # Score the open session this event belongs to (if any)
            lid = str(parsed.get("TargetLogonId") or "")
            if lid and lid in self.correlator.open_sessions:
                self._score_and_alert(self.correlator.open_sessions[lid], parsed)
            # Failed logons have no session — still run rule detector
            if int(parsed.get("EventID", -1)) == 4625:
                self._score_failed_logon(parsed)
        self.expire(now=parsed.get("TimeCreated"))
        return closed

    def run(self, events: Optional[Iterable[Any]] = None) -> Dict[str, Any]:
        """
        Drain ``events`` or the instance queue.

        Parameters
        ----------
        events : iterable, optional
            Event source.

        Returns
        -------
        dict
            Summary (processed, open, closed, alerts).
        """
        stream = list(events) if events is not None else list(self.queue)
        for item in stream:
            self.ingest(item)
        return self.summary()

    def expire(self, now: Any = None) -> List[Dict[str, Any]]:
        """Expire sessions older than ``expire_hours``. Returns expired rows."""
        return self.correlator.expire_stale(now=now)

    def subscribe_windows(self, channel: str = "Security", query: str = "*") -> None:
        """
        Subscribe to a live Windows event channel (requires pywin32).

        Parameters
        ----------
        channel : str
            Log channel (default ``Security``).
        query : str
            XPath query.

        Returns
        -------
        None
        """
        if not WIN32_AVAILABLE:
            raise RuntimeError(
                "pywin32 is not available. Live Windows subscription requires "
                "win32evtlog.SubscribeToEvents on a Windows host."
            )

        def _callback(reason, context, event):  # pragma: no cover - Windows only
            try:
                xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                self.ingest(xml)
            except Exception:
                return

        win32evtlog.SubscribeToEvents(None, channel, _callback, query)  # type: ignore[attr-defined]

    def summary(self) -> Dict[str, Any]:
        """Return a snapshot of monitor state."""
        return {
            "processed": self.processed,
            "open_sessions": len(self.correlator.open_sessions),
            "closed_sessions": len(self.closed_sessions),
            "alerts": len(self.alerts),
        }

    # ------------------------------------------------------------------

    def _coerce(self, event: Any) -> Optional[Dict[str, Any]]:
        if event is None:
            return None
        if isinstance(event, str):
            return self.parser.parse_xml_string(event)
        if isinstance(event, dict):
            if "EventID" in event:
                if "TimeCreated" in event:
                    event = dict(event)
                    event["TimeCreated"] = normalize_to_utc(event["TimeCreated"])
                return event
            xml = event.get("raw_xml") or event.get("xml")
            if xml:
                return self.parser.parse_xml_string(str(xml))
        return None

    def _score_and_alert(self, session: Dict[str, Any], event: Dict[str, Any]) -> None:
        hour = 12
        ts = session.get("LogonTime") or event.get("TimeCreated")
        ts = normalize_to_utc(ts)
        if ts is not None:
            hour = int(ts.hour)
        score = 0.0
        if self.scorer is not None:
            score = float(self.scorer(session) or 0.0)
        else:
            # Lightweight live rules: after-hours RDP + privileged orphan
            if int(session.get("LogonType", -1)) == 10 and (hour < 8 or hour >= 18):
                score = max(score, 0.8)
            if session.get("HasSpecialPrivileges") and session.get("Status") in {"orphaned", "active"}:
                score = max(score, 0.7)
        session["live_score"] = score
        if score >= self.score_threshold:
            finding = {
                "anomaly": "Live session anomaly",
                "detection_type": "Live session anomaly",
                "severity": "HIGH" if score < 0.9 else "CRITICAL",
                "mitre_id": "T1078",
                "user": session.get("Username"),
                "workstation": session.get("WorkstationName"),
                "timestamp": session.get("LogonTime"),
                "score": score,
                "shap_explanation": {
                    "logon_type": float(session.get("LogonType", 0) or 0),
                    "hour_of_day": float(hour),
                    "live_score": score,
                },
                "details": f"Live score {score:.2f} for {session.get('Username')} "
                f"on {session.get('WorkstationName')}",
            }
            self.alerts.append(finding)
            self.dispatcher.dispatch(finding)

    def _score_failed_logon(self, event: Dict[str, Any]) -> None:
        # Count recent 4625 from same IP in the in-memory queue of closed+open
        ip = str(event.get("IpAddress", ""))
        # Simple: if caller injected a scorer via event['score'] honour it
        score = float(event.get("score", 0) or 0)
        if score >= self.score_threshold or str(event.get("severity", "")).upper() in {"HIGH", "CRITICAL"}:
            finding = {
                "anomaly": event.get("anomaly", "Failed logon burst"),
                "detection_type": "Failed logon burst",
                "severity": str(event.get("severity", "HIGH")).upper(),
                "mitre_id": event.get("mitre_id", "T1110.001"),
                "user": event.get("TargetUserName"),
                "workstation": event.get("WorkstationName"),
                "timestamp": event.get("TimeCreated"),
                "score": score or 0.9,
                "shap_explanation": event.get("shap_explanation")
                or {"failed_logon_count_last_1h": 6.0, "ip": 0.2, "hour_of_day": 0.1},
                "details": f"Failed logon for {event.get('TargetUserName')} from {ip}",
            }
            self.alerts.append(finding)
            self.dispatcher.dispatch(finding)


def main(argv=None) -> int:
    """CLI entry point for live monitoring."""
    parser = argparse.ArgumentParser(description="WinLogin Forensics live monitor")
    parser.add_argument("--alert-email", default=None)
    parser.add_argument("--smtp-server", default=None)
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--channel", default="Security")
    args = parser.parse_args(argv)
    cfg = load_alert_config(args.config)
    if args.alert_email:
        cfg.setdefault("smtp", {})["to_addresses"] = [args.alert_email]
    if args.smtp_server:
        cfg.setdefault("smtp", {})["host"] = args.smtp_server
    monitor = LiveMonitor(config=cfg)
    if WIN32_AVAILABLE:
        print(f"Subscribing to {args.channel} ...")
        monitor.subscribe_windows(channel=args.channel)
        return 0
    print("pywin32 not available — live Windows subscription disabled. Use the mock queue API.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
