"""Events — filterable table of parsed authentication events."""

from __future__ import annotations

import streamlit as st

from src.ui.components.tables import show_table
from src.ui.theme import inject, require_result


def render() -> None:
    """Render the Events page."""
    inject()
    result = require_result()
    st.title("Events")
    df = result.events
    if df.empty:
        st.warning("No events parsed.")
        return

    c1, c2, c3 = st.columns(3)
    eids = sorted(df["EventID"].dropna().unique().tolist()) if "EventID" in df.columns else []
    users = sorted({str(u) for u in df.get("TargetUserName", []) if str(u) not in {"-", "nan"}})
    pick_eid = c1.multiselect("Event ID", eids)
    pick_user = c2.multiselect("User", users)
    query = c3.text_input("Search IP / workstation")

    view = df.copy()
    if pick_eid:
        view = view[view["EventID"].isin(pick_eid)]
    if pick_user:
        view = view[view["TargetUserName"].astype(str).isin(pick_user)]
    if query:
        mask = view.astype(str).apply(lambda col: col.str.contains(query, case=False, na=False)).any(axis=1)
        view = view[mask]

    st.caption(f"{len(view)} / {len(df)} events")
    show_table(
        view,
        [
            "TimeCreated",
            "EventID",
            "TargetUserName",
            "SubjectUserName",
            "TargetLogonId",
            "LogonType",
            "IpAddress",
            "IpPort",
            "WorkstationName",
            "Status",
            "Description",
        ],
    )
