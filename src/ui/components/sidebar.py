"""Sidebar navigation + case status."""

from __future__ import annotations

import streamlit as st


PAGES = [
    ("Home", "home"),
    ("Events", "events"),
    ("Registry", "registry"),
    ("Sessions", "sessions"),
    ("Anomalies", "anomalies"),
    ("Timeline", "timeline"),
    ("ATT&CK Matrix", "attack_matrix"),
    ("Real-Time", "realtime"),
    ("Benchmark", "benchmark"),
    ("Report", "report"),
]


def render_sidebar() -> str:
    """
    Draw the sidebar and return the selected page key.

    Returns
    -------
    str
        Page identifier.
    """
    with st.sidebar:
        st.markdown('<div class="wl-brand">WINLOGIN FORENSICS</div>', unsafe_allow_html=True)
        st.markdown('<div class="wl-sub">Authentication artefact workbench</div>', unsafe_allow_html=True)
        labels = [p[0] for p in PAGES]
        choice = st.radio("Navigate", labels, label_visibility="collapsed")
        st.divider()
        result = st.session_state.get("result")
        if result is not None:
            st.caption("Case loaded")
            st.write(st.session_state.get("case_name", "Untitled case"))
            st.metric("Events", len(result.events))
            st.metric("Sessions", len(result.sessions))
            st.metric("Findings", len(result.anomalies) + len(result.antiforensic))
        else:
            st.caption("No case loaded")
    for label, key in PAGES:
        if label == choice:
            return key
    return "home"
