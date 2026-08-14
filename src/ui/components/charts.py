"""Plotly chart helpers for the Streamlit UI."""

from __future__ import annotations

from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


TEMPLATE = "plotly_dark"


def event_id_bar(events: pd.DataFrame):
    """Bar chart of EventID counts."""
    if events is None or events.empty or "EventID" not in events.columns:
        return go.Figure()
    counts = events["EventID"].value_counts().reset_index()
    counts.columns = ["EventID", "count"]
    fig = px.bar(counts, x="EventID", y="count", template=TEMPLATE, title="Events by ID")
    fig.update_layout(margin=dict(l=10, r=10, t=40, b=10), height=320)
    return fig


def session_gantt(sessions: pd.DataFrame):
    """Horizontal timeline of sessions."""
    if sessions is None or sessions.empty:
        return go.Figure()
    df = sessions.copy()
    start = df.get("LogonTime", df.get("StartTime"))
    end = df.get("LogoffTime", df.get("EndTime"))
    df = df.assign(start=pd.to_datetime(start, utc=True, errors="coerce"))
    df["end"] = pd.to_datetime(end, utc=True, errors="coerce")
    df["end"] = df["end"].fillna(df["start"] + pd.Timedelta(minutes=15))
    df["label"] = df.get("Username", pd.Series(["?"] * len(df))).astype(str) + " · " + df.get("SessionID", "").astype(str)
    fig = px.timeline(df, x_start="start", x_end="end", y="label", color="Status", template=TEMPLATE, title="Session timeline")
    fig.update_yaxes(autorange="reversed")
    fig.update_layout(margin=dict(l=10, r=10, t=40, b=10), height=420)
    return fig


def mitre_heatmap(matrix: List[Dict[str, Any]]):
    """Heatmap-style bar of detected vs tracked techniques."""
    if not matrix:
        return go.Figure()
    df = pd.DataFrame(matrix)
    df["count"] = df.get("count", 0)
    fig = px.bar(
        df.sort_values("count", ascending=False),
        x="mitre_id",
        y="count",
        color="detected",
        hover_data=["name", "tactic", "severity"],
        template=TEMPLATE,
        title="MITRE ATT&CK technique hits",
    )
    fig.update_layout(margin=dict(l=10, r=10, t=40, b=10), height=360)
    return fig


def shap_bar(explanation: Dict[str, float]):
    """Horizontal bar of SHAP feature contributions."""
    if not explanation:
        return go.Figure()
    items = sorted(explanation.items(), key=lambda kv: abs(float(kv[1] or 0)))
    fig = go.Figure(
        go.Bar(
            x=[float(v) for _, v in items],
            y=[k for k, _ in items],
            orientation="h",
            marker_color=["#38bdf8" if float(v) >= 0 else "#f97316" for _, v in items],
        )
    )
    fig.update_layout(template=TEMPLATE, title="SHAP feature contributions", height=320, margin=dict(l=10, r=10, t=40, b=10))
    return fig
