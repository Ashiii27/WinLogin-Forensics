"""Shared Streamlit chrome — dark forensic theme + metric helpers."""

from __future__ import annotations

from typing import Any, Optional

import pandas as pd
import streamlit as st


CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
html, body, [class*="css"]  { font-family: "IBM Plex Sans", "Segoe UI", sans-serif; }
.stApp { background: #0b1220; color: #e2e8f0; }
section[data-testid="stSidebar"] { background: #0e1729; border-right: 1px solid #1e293b; }
h1, h2, h3 { color: #f8fafc !important; letter-spacing: -0.02em; }
div[data-testid="stMetric"] {
  background: linear-gradient(180deg, #151d2e 0%, #101827 100%);
  border: 1px solid #1e293b; border-radius: 12px; padding: 12px 14px;
}
div[data-testid="stMetric"] label { color: #94a3b8 !important; }
.wl-brand { font-size: 1.15rem; font-weight: 700; color: #38bdf8; letter-spacing: 0.04em; }
.wl-sub { color: #64748b; font-size: 0.8rem; margin-bottom: 1rem; }
.wl-chip {
  display: inline-block; padding: 2px 8px; border-radius: 999px;
  font-size: 0.72rem; font-weight: 600; letter-spacing: 0.04em;
}
.wl-high { background: #7f1d1d; color: #fecaca; }
.wl-medium { background: #78350f; color: #fde68a; }
.wl-low { background: #14532d; color: #bbf7d0; }
.wl-mono { font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 0.8rem; color: #93c5fd; }
hr { border-color: #1e293b; }
</style>
"""


def inject() -> None:
    """Inject the shared CSS once per page."""
    st.markdown(CSS, unsafe_allow_html=True)


def severity_chip(label: Any) -> str:
    """Return an HTML chip for a severity label."""
    text = str(label or "Low")
    cls = "wl-low"
    if text.lower().startswith("h") or text.lower() == "critical":
        cls = "wl-high"
    elif text.lower().startswith("m"):
        cls = "wl-medium"
    return f'<span class="wl-chip {cls}">{text}</span>'


def ensure_result():
    """Return the AnalysisResult in session state, or None."""
    return st.session_state.get("result")


def require_result():
    """Render a hint and stop if no analysis has been run."""
    result = ensure_result()
    if result is None:
        st.info("Load evidence or the demo case on **Home**, then run analysis.")
        st.stop()
    return result


def df_or_empty(frame: Optional[pd.DataFrame]) -> pd.DataFrame:
    """Return a DataFrame, never None."""
    if frame is None:
        return pd.DataFrame()
    return frame
