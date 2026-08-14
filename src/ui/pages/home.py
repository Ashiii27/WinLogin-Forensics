"""Home — upload evidence, run analysis, summary stats."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from src.analysis.pipeline import AnalysisPipeline
from src.ui.components.charts import event_id_bar
from src.ui.theme import inject
from src.utils.demo_data import load_demo_frames


def render() -> None:
    """Render the Home page."""
    inject()
    st.title("Investigation workspace")
    st.caption("Upload Windows evidence or load the built-in CORP-DC01 demo case.")

    col_a, col_b = st.columns((2, 1))
    with col_a:
        evtx_files = st.file_uploader(
            "EVTX / XML / JSON event logs",
            type=["evtx", "xml", "json", "csv"],
            accept_multiple_files=True,
        )
        hive_files = st.file_uploader(
            "Registry hives / JSON exports (SAM, SOFTWARE, NTUSER)",
            type=["json", "dat", "hiv", "hive"],
            accept_multiple_files=True,
        )
    with col_b:
        operator = st.text_input("Examiner", value="analyst")
        threshold = st.slider("Score threshold", 0.0, 1.0, 0.5, 0.05)
        st.write("")
        load_demo = st.button("Load demo case", use_container_width=True, type="primary")
        run_btn = st.button("Run analysis on uploads", use_container_width=True)

    if load_demo:
        demo = load_demo_frames()
        with st.spinner("Running full analysis on demo case…"):
            pipe = AnalysisPipeline(
                events=demo["events"],
                sysmon=demo["sysmon"],
                powershell=demo["powershell"],
                registry=demo["registry"],
                operator=operator,
                threshold=threshold,
            )
            result = pipe.run()
        st.session_state.result = result
        st.session_state.case_name = demo["case_name"]
        st.session_state.case_notes = demo["notes"]
        st.success(f"Demo case loaded — {len(result.events)} events, {len(result.anomalies)} anomalies.")

    if run_btn:
        tmp = Path(st.session_state.get("tmp_dir") or "/tmp/winlogin_uploads")
        tmp.mkdir(parents=True, exist_ok=True)
        saved = []
        for up in evtx_files or []:
            dest = tmp / up.name
            dest.write_bytes(up.getvalue())
            saved.append(dest)
        hive_dir = tmp / "hives"
        hive_dir.mkdir(exist_ok=True)
        for up in hive_files or []:
            (hive_dir / up.name).write_bytes(up.getvalue())
        if not saved:
            st.warning("Upload at least one event log, or use the demo case.")
        else:
            with st.spinner("Parsing and analysing…"):
                pipe = AnalysisPipeline(
                    evtx_paths=saved,
                    hive_dir=hive_dir if hive_files else None,
                    operator=operator,
                    threshold=threshold,
                    output_dir=tmp / "out",
                )
                result = pipe.run()
            st.session_state.result = result
            st.session_state.case_name = saved[0].name
            st.success(f"Analysed {len(result.events)} events.")

    result = st.session_state.get("result")
    if result is None:
        st.info("No case in memory yet.")
        return

    st.subheader(st.session_state.get("case_name", "Current case"))
    if st.session_state.get("case_notes"):
        st.write(st.session_state["case_notes"])

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Events", result.event_stats.get("total", len(result.events)))
    c2.metric("Sessions", result.session_stats.get("total", len(result.sessions)))
    c3.metric("Orphaned", result.session_stats.get("orphaned", 0))
    c4.metric("Anomalies", len(result.anomalies))
    c5.metric("Anti-forensic", len(result.antiforensic))

    if not result.events.empty:
        st.plotly_chart(event_id_bar(result.events), use_container_width=True)
