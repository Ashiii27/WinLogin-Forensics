"""ATT&CK Matrix — navigator-style heatmap of triggered techniques."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.ui.components.charts import mitre_heatmap
from src.ui.theme import inject, require_result, severity_chip


def render() -> None:
    """Render the ATT&CK matrix page."""
    inject()
    result = require_result()
    st.title("MITRE ATT&CK coverage")
    stats = result.mitre_stats or {}
    c1, c2, c3 = st.columns(3)
    c1.metric("Techniques tracked", stats.get("total_techniques_tracked", 0))
    c2.metric("Detected", stats.get("techniques_detected", 0))
    c3.metric("Coverage", f"{stats.get('coverage_percent', 0)}%")

    st.plotly_chart(mitre_heatmap(result.mitre_matrix), use_container_width=True)

    st.subheader("Technique catalogue")
    for row in result.mitre_matrix or []:
        mark = "●" if row.get("detected") else "○"
        st.markdown(
            f"{mark} **{row.get('mitre_id')}** — {row.get('name')} "
            f"({row.get('tactic')})  {severity_chip(row.get('severity'))}  "
            f"hits={row.get('count', 0)}",
            unsafe_allow_html=True,
        )
