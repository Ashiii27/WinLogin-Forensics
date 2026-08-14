"""Sessions — timeline, orphaned list, overlap heatmap."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from src.ui.components.charts import session_gantt
from src.ui.components.tables import show_table
from src.ui.theme import inject, require_result


def render() -> None:
    """Render the Sessions page."""
    inject()
    result = require_result()
    st.title("Sessions")
    df = result.enriched_sessions if result.enriched_sessions is not None and not result.enriched_sessions.empty else result.sessions
    if df is None or df.empty:
        st.warning("No sessions reconstructed.")
        return

    c1, c2, c3 = st.columns(3)
    c1.metric("Total", len(df))
    status = df["Status"].astype(str).str.lower() if "Status" in df.columns else pd.Series(dtype=str)
    c2.metric("Orphaned", int(status.str.contains("orphan").sum()) if len(status) else 0)
    c3.metric("Overlapping", int(df["OverlapFlag"].sum()) if "OverlapFlag" in df.columns else 0)

    st.plotly_chart(session_gantt(df), use_container_width=True)

    st.subheader("Orphaned sessions")
    orphaned = df[status.str.contains("orphan")] if len(status) else df.iloc[0:0]
    show_table(orphaned, ["SessionID", "Username", "TargetLogonId", "LogonTypeName", "IpAddress", "WorkstationName", "LogonTime", "HasSpecialPrivileges"])

    if "OverlapFlag" in df.columns and df["OverlapFlag"].any():
        st.subheader("Overlap heatmap")
        heat = df[df["OverlapFlag"]][["Username", "WorkstationName", "SessionID"]]
        if not heat.empty:
            pivot = pd.crosstab(heat["Username"], heat["WorkstationName"])
            fig = px.imshow(pivot, aspect="auto", template="plotly_dark", title="Overlapping sessions by user × workstation")
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("All sessions")
    show_table(
        df,
        [
            "SessionID",
            "Username",
            "TargetLogonId",
            "LogonTypeName",
            "IpAddress",
            "WorkstationName",
            "LogonTime",
            "LogoffTime",
            "DurationFormatted",
            "Status",
            "OverlapFlag",
        ],
    )
