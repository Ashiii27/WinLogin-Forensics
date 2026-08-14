"""Benchmark — side-by-side detection rate vs peer tools."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from benchmarking.run_all import run_benchmark
from src.ui.theme import inject


def render() -> None:
    """Render the Benchmark page."""
    inject()
    st.title("Tool benchmark")
    st.caption("WinLogin vs Chainsaw, Hayabusa, DeepBlueCLI, and Plaso on the labeled corpus.")

    sample_dir = Path("evaluation/samples")
    out_csv = Path("benchmarking/results/comparison.csv")
    if st.button("Run benchmark", type="primary"):
        with st.spinner("Scoring labeled samples…"):
            rows = run_benchmark(sample_dir, out_csv)
        st.session_state.benchmark_rows = rows
        st.success(f"Wrote {out_csv}")

    rows = st.session_state.get("benchmark_rows")
    if rows is None and out_csv.exists():
        rows = pd.read_csv(out_csv).to_dict(orient="records")

    if not rows:
        st.info("Run the harness to populate results.")
        return

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True)
    fig = px.bar(
        df,
        x="tool",
        y=["detection_rate", "false_positive_rate"],
        barmode="group",
        template="plotly_dark",
        title="Detection rate vs false-positive rate",
    )
    st.plotly_chart(fig, use_container_width=True)
    fig2 = px.bar(df, x="tool", y="seconds_per_1000_events", template="plotly_dark", title="Processing time per 1,000 events")
    st.plotly_chart(fig2, use_container_width=True)
