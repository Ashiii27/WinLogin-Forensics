"""Report — generate and download HTML / PDF forensic reports."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from src.report.html_generator import CaseInfo, HtmlReportGenerator, ReportData
from src.report.pdf_generator import PdfReportGenerator
from src.ui.theme import inject, require_result


def render() -> None:
    """Render the Report page."""
    inject()
    result = require_result()
    st.title("Forensic report")

    c1, c2 = st.columns(2)
    case_no = c1.text_input("Case number", value="CASE-2026-0812")
    investigator = c2.text_input("Investigator", value=result.custody.operator if result.custody else "analyst")
    org = st.text_input("Organization", value="CORP IR")
    sign = st.checkbox("Digitally sign report (RSA-PSS)", value=False)

    out_dir = Path("output/reports")
    out_dir.mkdir(parents=True, exist_ok=True)

    data = ReportData(
        case=CaseInfo(case_number=case_no, investigator=investigator, organization=org),
        events=result.events,
        sessions=result.sessions,
        anomalies=result.anomalies,
        antiforensic=result.antiforensic,
        registry=result.registry,
        ml_results=result.ml_params,
        custody=result.custody,
        source_files=result.custody.source_files if result.custody else [],
        appendix_notes=st.session_state.get("case_notes", ""),
    )

    col_a, col_b = st.columns(2)
    if col_a.button("Generate HTML", type="primary"):
        html_path = out_dir / "report.html"
        html = HtmlReportGenerator().generate_html(data, output_path=html_path, sign=sign)
        st.session_state.last_html = html
        st.session_state.last_html_path = str(html_path)
        st.success(f"Wrote {html_path}")
    if col_b.button("Generate PDF"):
        pdf_path = out_dir / "report.pdf"
        written = PdfReportGenerator().generate(data, pdf_path, sign=sign, custody=result.custody)
        st.session_state.last_pdf_path = str(written)
        st.success(f"Wrote {written}")

    if st.session_state.get("last_html"):
        st.download_button("Download HTML", data=st.session_state["last_html"], file_name="winlogin_report.html", mime="text/html")
        with st.expander("Preview"):
            st.components.v1.html(st.session_state["last_html"], height=640, scrolling=True)
    if st.session_state.get("last_pdf_path") and Path(st.session_state["last_pdf_path"]).exists():
        st.download_button(
            "Download PDF",
            data=Path(st.session_state["last_pdf_path"]).read_bytes(),
            file_name="winlogin_report.pdf",
            mime="application/pdf",
        )
