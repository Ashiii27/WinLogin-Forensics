"""Timeline — unified chronological event / session / process view."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from src.ui.components.tables import show_table
from src.ui.theme import inject, require_result


def render() -> None:
    """Render the Timeline page."""
    inject()
    result = require_result()
    st.title("Unified timeline")

    rows = []
    if result.events is not None and not result.events.empty:
        for _, ev in result.events.iterrows():
            rows.append(
                {
                    "Time": ev.get("TimeCreated"),
                    "Kind": "Event",
                    "Actor": ev.get("TargetUserName"),
                    "Detail": f"EID {ev.get('EventID')} {ev.get('Description', '')}",
                    "Host": ev.get("WorkstationName"),
                }
            )
    if result.sessions is not None and not result.sessions.empty:
        for _, sess in result.sessions.iterrows():
            rows.append(
                {
                    "Time": sess.get("LogonTime"),
                    "Kind": "Session start",
                    "Actor": sess.get("Username"),
                    "Detail": f"{sess.get('SessionID')} {sess.get('LogonTypeName')}",
                    "Host": sess.get("WorkstationName"),
                }
            )
    if result.sysmon is not None and not result.sysmon.empty:
        for _, sm in result.sysmon.iterrows():
            rows.append(
                {
                    "Time": sm.get("UtcTime") or sm.get("TimeCreated"),
                    "Kind": f"Sysmon {sm.get('EventID')}",
                    "Actor": sm.get("User"),
                    "Detail": sm.get("CommandLine") or sm.get("QueryName") or sm.get("TargetFilename") or sm.get("DestinationIp"),
                    "Host": "",
                }
            )
    if result.powershell is not None and not result.powershell.empty:
        for _, ps in result.powershell.iterrows():
            rows.append(
                {
                    "Time": ps.get("TimeCreated"),
                    "Kind": "PowerShell",
                    "Actor": ps.get("User"),
                    "Detail": str(ps.get("ScriptBlockText", ""))[:160],
                    "Host": "",
                }
            )

    timeline = pd.DataFrame(rows)
    if timeline.empty:
        st.info("Nothing to plot.")
        return
    timeline["Time"] = pd.to_datetime(timeline["Time"], utc=True, errors="coerce")
    timeline = timeline.dropna(subset=["Time"]).sort_values("Time")

    fig = px.scatter(
        timeline,
        x="Time",
        y="Kind",
        color="Kind",
        hover_data=["Actor", "Detail", "Host"],
        template="plotly_dark",
        title="Event · session · process timeline",
    )
    fig.update_layout(height=420, margin=dict(l=10, r=10, t=40, b=10))
    st.plotly_chart(fig, use_container_width=True)
    show_table(timeline, ["Time", "Kind", "Actor", "Host", "Detail"], height=360)
