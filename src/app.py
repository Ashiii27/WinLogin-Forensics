#!/usr/bin/env python3
"""
WinLogin Forensics - Streamlit entrypoint
=========================================
Dark-themed SOC workbench. Bind to 0.0.0.0 so the sandbox preview works.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from src.ui.components.sidebar import render_sidebar
from src.ui.pages import (
    anomalies,
    attack_matrix,
    benchmark,
    events,
    home,
    realtime,
    registry,
    report,
    sessions,
    timeline,
)
from src.ui.theme import inject


st.set_page_config(
    page_title="WinLogin Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


PAGES = {
    "home": home.render,
    "events": events.render,
    "registry": registry.render,
    "sessions": sessions.render,
    "anomalies": anomalies.render,
    "timeline": timeline.render,
    "attack_matrix": attack_matrix.render,
    "realtime": realtime.render,
    "benchmark": benchmark.render,
    "report": report.render,
}


def main() -> None:
    """Dispatch the selected sidebar page."""
    inject()
    key = render_sidebar()
    PAGES.get(key, home.render)()


main()
