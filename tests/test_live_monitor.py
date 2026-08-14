"""Phase 7 — Live monitor + alert dispatcher tests."""

from __future__ import annotations

from src.live.alert_dispatcher import AlertDispatcher
from src.live.live_monitor import LiveMonitor


class _FakeSMTP:
    def __init__(self):
        self.messages = []

    def send_message(self, msg):
        self.messages.append(msg)


def test_session_state_updates_from_mock_queue():
    queue = [
        {
            "EventID": 4624,
            "TimeCreated": "2026-08-12T09:00:00Z",
            "TargetUserName": "alice",
            "TargetLogonId": "0xabc",
            "LogonType": 2,
            "WorkstationName": "WS1",
            "IpAddress": "10.0.0.8",
        },
        {
            "EventID": 4625,
            "TimeCreated": "2026-08-12T09:01:00Z",
            "TargetUserName": "bob",
            "TargetLogonId": "0x0",
            "LogonType": 3,
            "WorkstationName": "WS1",
            "IpAddress": "185.220.101.5",
        },
        {
            "EventID": 4634,
            "TimeCreated": "2026-08-12T09:30:00Z",
            "TargetUserName": "alice",
            "TargetLogonId": "0xabc",
            "LogonType": 2,
            "WorkstationName": "WS1",
        },
    ]
    monitor = LiveMonitor(queue=queue, score_threshold=0.99)
    summary = monitor.run()
    assert summary["processed"] == 3
    assert summary["closed_sessions"] == 1
    assert summary["open_sessions"] == 0
    assert monitor.closed_sessions[0]["Username"] == "alice"
    assert monitor.closed_sessions[0]["DurationSeconds"] == 1800


def test_alert_fires_when_score_exceeds_threshold():
    smtp = _FakeSMTP()
    dispatcher = AlertDispatcher(
        config={
            "smtp": {"host": "localhost", "port": 25, "from_address": "a@b.c", "to_addresses": ["soc@b.c"]},
            "thresholds": {"score": 0.7, "severities": ["HIGH", "CRITICAL"]},
        },
        smtp_client=smtp,
    )

    def scorer(session):
        return 0.91 if session.get("Username") == "Administrator" else 0.1

    monitor = LiveMonitor(dispatcher=dispatcher, scorer=scorer, score_threshold=0.7)
    monitor.ingest(
        {
            "EventID": 4624,
            "TimeCreated": "2026-08-12T02:15:00Z",
            "TargetUserName": "Administrator",
            "TargetLogonId": "0xevil",
            "LogonType": 10,
            "WorkstationName": "DC01",
            "IpAddress": "185.220.101.5",
        }
    )
    assert monitor.alerts, "expected a live alert"
    assert monitor.alerts[0]["severity"] in {"HIGH", "CRITICAL"}
    assert smtp.messages, "expected SMTP send"
    body = smtp.messages[0].get_content()
    assert "Administrator" in body
    assert "DC01" in body
    assert "T1078" in body or "MITRE" in body
    assert "SHAP" in body or "shap" in body.lower() or "hour_of_day" in body


def test_dispatcher_suppresses_low_severity():
    smtp = _FakeSMTP()
    disp = AlertDispatcher(
        config={"smtp": {"to_addresses": ["x@y.z"], "from_address": "a@b.c"}, "thresholds": {"score": 0.8, "severities": ["HIGH"]}},
        smtp_client=smtp,
    )
    assert disp.dispatch({"severity": "LOW", "score": 0.2, "anomaly": "noise"}) is None
    assert smtp.messages == []
