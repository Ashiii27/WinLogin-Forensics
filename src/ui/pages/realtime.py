"""Real-Time — live stream view, active sessions, alert feed."""

from __future__ import annotations

import streamlit as st

from src.live.alert_dispatcher import AlertDispatcher
from src.live.live_monitor import LiveMonitor
from src.ui.theme import inject
from src.utils.demo_data import build_demo_events


def render() -> None:
    """Render the Real-Time page (simulated stream from the demo case)."""
    inject()
    st.title("Real-time monitor")
    st.caption("Replays a mock event queue through the incremental correlator and alerter.")

    if "live_monitor" not in st.session_state:
        st.session_state.live_monitor = LiveMonitor(score_threshold=0.7)
        st.session_state.live_cursor = 0
        st.session_state.live_queue = build_demo_events()

    monitor: LiveMonitor = st.session_state.live_monitor
    queue = st.session_state.live_queue

    c1, c2, c3 = st.columns(3)
    step = c1.button("Ingest next event")
    burst = c2.button("Ingest next 10")
    reset = c3.button("Reset stream")

    if reset:
        st.session_state.live_monitor = LiveMonitor(score_threshold=0.7)
        st.session_state.live_cursor = 0
        st.rerun()

    n = 1 if step else 10 if burst else 0
    for _ in range(n):
        idx = st.session_state.live_cursor
        if idx >= len(queue):
            st.warning("Queue exhausted.")
            break
        monitor.ingest(queue[idx])
        st.session_state.live_cursor = idx + 1

    summary = monitor.summary()
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Processed", summary["processed"])
    m2.metric("Active sessions", summary["open_sessions"])
    m3.metric("Closed sessions", summary["closed_sessions"])
    m4.metric("Alerts", summary["alerts"])

    st.subheader("Active sessions")
    if monitor.sessions:
        st.json({k: {"user": v.get("Username"), "status": v.get("Status"), "type": v.get("LogonType")} for k, v in monitor.sessions.items()})
    else:
        st.caption("None open.")

    st.subheader("Alert feed")
    if monitor.alerts:
        for alert in reversed(monitor.alerts):
            st.error(
                f"{alert.get('severity')} · {alert.get('anomaly')} · "
                f"{alert.get('user')} @ {alert.get('workstation')} · {alert.get('mitre_id')}"
            )
    else:
        st.caption("No alerts yet — keep ingesting.")
