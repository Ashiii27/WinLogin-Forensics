"""Anomalies — table, SHAP waterfall, MITRE tag, severity badge."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.ui.components.charts import shap_bar
from src.ui.theme import inject, require_result, severity_chip


def render() -> None:
    """Render the Anomalies page."""
    inject()
    result = require_result()
    st.title("Anomalies")

    findings = list(result.anomalies or []) + list(result.graph_findings or [])
    if not findings:
        st.info("No anomalies flagged.")
        return

    rows = []
    for f in findings:
        rows.append(
            {
                "Time": str(f.get("timestamp") or ""),
                "Finding": f.get("anomaly") or f.get("detection_type"),
                "Severity": f.get("severity"),
                "MITRE": f.get("mitre_id"),
                "Details": f.get("details") or f.get("evidence_detail"),
                "Confidence": f.get("confidence") or f.get("score") or f.get("ensemble_score"),
                "_shap": f.get("shap_explanation") or f.get("shap") or {},
            }
        )
    table = pd.DataFrame(rows)
    sev_filter = st.multiselect("Severity", sorted({str(s) for s in table["Severity"].dropna()}), default=None)
    view = table if not sev_filter else table[table["Severity"].astype(str).isin(sev_filter)]

    for _, row in view.iterrows():
        with st.container():
            c1, c2, c3 = st.columns((4, 1, 1))
            c1.markdown(f"**{row['Finding']}**  \n{row['Details']}")
            c2.markdown(severity_chip(row["Severity"]), unsafe_allow_html=True)
            c3.markdown(f'`{row["MITRE"]}`')
            shap = row["_shap"]
            if isinstance(shap, dict) and shap:
                st.plotly_chart(shap_bar(shap), use_container_width=True)
            st.divider()

    if result.scored is not None and not result.scored.empty:
        st.subheader("ML ensemble scores")
        st.dataframe(
            result.scored[
                [c for c in ("SessionID", "Username", "ensemble_score", "iforest_score", "ocsvm_score", "is_anomaly") if c in result.scored.columns]
            ],
            use_container_width=True,
        )
