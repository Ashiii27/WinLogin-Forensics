"""
WinLogin Forensics - PDF Report Generator
=========================================
Exports HTML forensic reports to PDF. Prefers pdfkit (wkhtmltopdf) and
falls back to ReportLab so generation works in environments without
wkhtmltopdf.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

from .html_generator import HtmlReportGenerator, ReportData
from .integrity import ChainOfCustody, compute_sha256, hash_file

try:
    import pdfkit
    PDFKIT_AVAILABLE = True
except ImportError:
    PDFKIT_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


DEFAULT_PDF_OPTIONS = {
    "page-size": "A4",
    "margin-top": "15mm",
    "margin-right": "15mm",
    "margin-bottom": "20mm",
    "margin-left": "15mm",
    "encoding": "UTF-8",
    "enable-local-file-access": None,
    "footer-center": "WinLogin Forensics — Page [page] of [topage]",
    "footer-font-size": "8",
    "print-media-type": None,
}

# ── colour palette ──────────────────────────────────────────────────────────
DARK_BG   = colors.HexColor("#1a1a2e")
ACCENT    = colors.HexColor("#4f8ef7")
HIGH_CLR  = colors.HexColor("#e74c3c")
MED_CLR   = colors.HexColor("#f39c12")
LOW_CLR   = colors.HexColor("#2ecc71")
TBL_HEAD  = colors.HexColor("#16213e")
TBL_ALT   = colors.HexColor("#f2f6ff")
BORDER    = colors.HexColor("#c8d6ef")
WHITE     = colors.white
BLACK     = colors.black
GREY      = colors.HexColor("#555555")


def _styles():
    """Return a dict of named ParagraphStyles."""
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "RPT_Title",
            parent=base["Title"],
            fontSize=20,
            textColor=DARK_BG,
            spaceAfter=4,
            fontName="Helvetica-Bold",
        ),
        "subtitle": ParagraphStyle(
            "RPT_Subtitle",
            parent=base["Normal"],
            fontSize=10,
            textColor=GREY,
            spaceAfter=2,
            fontName="Helvetica",
        ),
        "h1": ParagraphStyle(
            "RPT_H1",
            parent=base["Heading1"],
            fontSize=13,
            textColor=DARK_BG,
            spaceBefore=14,
            spaceAfter=4,
            fontName="Helvetica-Bold",
            borderPad=2,
        ),
        "h2": ParagraphStyle(
            "RPT_H2",
            parent=base["Heading2"],
            fontSize=11,
            textColor=ACCENT,
            spaceBefore=10,
            spaceAfter=3,
            fontName="Helvetica-Bold",
        ),
        "body": ParagraphStyle(
            "RPT_Body",
            parent=base["Normal"],
            fontSize=9,
            textColor=BLACK,
            spaceAfter=3,
            fontName="Helvetica",
            leading=13,
        ),
        "mono": ParagraphStyle(
            "RPT_Mono",
            parent=base["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#333333"),
            fontName="Courier",
            spaceAfter=2,
            leading=11,
        ),
        "label": ParagraphStyle(
            "RPT_Label",
            parent=base["Normal"],
            fontSize=8,
            textColor=GREY,
            fontName="Helvetica-Bold",
        ),
        "sev_high": ParagraphStyle(
            "RPT_SevHigh",
            parent=base["Normal"],
            fontSize=8,
            textColor=WHITE,
            fontName="Helvetica-Bold",
            backColor=HIGH_CLR,
        ),
        "sev_med": ParagraphStyle(
            "RPT_SevMed",
            parent=base["Normal"],
            fontSize=8,
            textColor=WHITE,
            fontName="Helvetica-Bold",
            backColor=MED_CLR,
        ),
        "sev_low": ParagraphStyle(
            "RPT_SevLow",
            parent=base["Normal"],
            fontSize=8,
            textColor=WHITE,
            fontName="Helvetica-Bold",
            backColor=LOW_CLR,
        ),
    }


def _tbl_style(header_rows=1):
    return TableStyle([
        # header
        ("BACKGROUND",  (0, 0), (-1, header_rows - 1), TBL_HEAD),
        ("TEXTCOLOR",   (0, 0), (-1, header_rows - 1), WHITE),
        ("FONTNAME",    (0, 0), (-1, header_rows - 1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, header_rows - 1), 8),
        ("ROWBACKGROUND", (0, header_rows), (-1, -1), [WHITE, TBL_ALT]),
        ("FONTNAME",    (0, header_rows), (-1, -1), "Helvetica"),
        ("FONTSIZE",    (0, header_rows), (-1, -1), 8),
        ("GRID",        (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",(0, 0), (-1, -1), 4),
        ("TOPPADDING",  (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0,0), (-1, -1), 3),
    ])


def _hr(story):
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))


def _severity_text(sev: str, st: dict) -> Paragraph:
    sev_lower = (sev or "").lower()
    style = st.get(f"sev_{sev_lower}", st["body"])
    return Paragraph(f" {sev.upper()} ", style)


def _safe(val) -> str:
    """Escape XML-unsafe chars for ReportLab paragraphs."""
    return str(val or "—").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_pdf_from_data(data: ReportData, out: Path) -> Path:
    """Build a fully structured PDF directly from ReportData."""
    st = _styles()
    page_w, page_h = A4
    usable_w = page_w - 30 * mm

    story = []

    # ── Cover / header ──────────────────────────────────────────────────────
    story.append(Paragraph("WinLogin Forensics", st["title"]))
    story.append(Paragraph("Forensic Analysis Report", st["subtitle"]))
    _hr(story)

    # Case metadata table
    case = data.case
    ts = getattr(data.custody, "started_at", None) or getattr(data.custody, "started", None) or "N/A"
    meta_rows = [
        ["Case Number",  _safe(case.case_number),   "Investigator", _safe(case.investigator)],
        ["Organization", _safe(case.organization),  "Analysis Date", _safe(ts)],
    ]
    meta_tbl = Table(meta_rows, colWidths=[35*mm, 60*mm, 35*mm, 60*mm])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",    (2,0), (2,-1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("TEXTCOLOR",   (0,0), (0,-1), GREY),
        ("TEXTCOLOR",   (2,0), (2,-1), GREY),
        ("GRID",        (0,0), (-1,-1), 0.3, BORDER),
        ("BACKGROUND",  (0,0), (0,-1), TBL_ALT),
        ("BACKGROUND",  (2,0), (2,-1), TBL_ALT),
        ("LEFTPADDING", (0,0), (-1,-1), 5),
        ("TOPPADDING",  (0,0), (-1,-1), 3),
        ("BOTTOMPADDING",(0,0),(-1,-1), 3),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 10))

    # ── Executive Summary ───────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", st["h1"]))
    _hr(story)

    events   = data.events   or []
    sessions = data.sessions or []
    anomalies= data.anomalies or []
    anti     = data.antiforensic or []

    n_high = sum(1 for a in anomalies if str(getattr(a, "severity", "") or "").lower() == "high")
    n_med  = sum(1 for a in anomalies if str(getattr(a, "severity", "") or "").lower() == "medium")
    n_low  = sum(1 for a in anomalies if str(getattr(a, "severity", "") or "").lower() == "low")
    orphaned = sum(1 for s in sessions if getattr(s, "status", "") == "orphaned")

    summary_rows = [
        ["Metric", "Value"],
        ["Total events parsed",        str(len(events))],
        ["Sessions identified",        str(len(sessions))],
        ["Orphaned sessions",          str(orphaned)],
        ["Anomalies detected",         str(len(anomalies))],
        ["  High severity",            str(n_high)],
        ["  Medium severity",          str(n_med)],
        ["  Low severity",             str(n_low)],
        ["Anti-forensic findings",     str(len(anti))],
    ]
    s_tbl = Table(summary_rows, colWidths=[100*mm, 80*mm])
    s_tbl.setStyle(_tbl_style())
    story.append(s_tbl)
    story.append(Spacer(1, 8))

    # Time range
    if events:
        times = [getattr(e, "time_created", None) for e in events if getattr(e, "time_created", None)]
        if times:
            story.append(Paragraph(
                f"Event time range: <b>{_safe(min(times))}</b> → <b>{_safe(max(times))}</b>",
                st["body"]
            ))

    # ── Anomalies ───────────────────────────────────────────────────────────
    if anomalies:
        story.append(Paragraph("Detected Anomalies", st["h1"]))
        _hr(story)
        anom_rows = [["Time", "Finding", "Severity", "MITRE", "Details"]]
        for a in anomalies:
            sev = _safe(getattr(a, "severity", ""))
            anom_rows.append([
                _safe(getattr(a, "time",     "")),
                _safe(getattr(a, "finding",  "")),
                sev,
                _safe(getattr(a, "mitre",    "")),
                _safe(getattr(a, "details",  "")),
            ])
        a_tbl = Table(anom_rows, colWidths=[32*mm, 35*mm, 18*mm, 20*mm, None])
        a_tbl.setStyle(_tbl_style())
        # colour severity cells
        for i, a in enumerate(anomalies, start=1):
            sev = str(getattr(a, "severity", "") or "").lower()
            clr = HIGH_CLR if sev == "high" else MED_CLR if sev == "medium" else LOW_CLR
            a_tbl.setStyle(TableStyle([("BACKGROUND", (2, i), (2, i), clr),
                                        ("TEXTCOLOR",  (2, i), (2, i), WHITE)]))
        story.append(a_tbl)
        story.append(Spacer(1, 8))

    # ── Session Timeline ─────────────────────────────────────────────────────
    if sessions:
        story.append(Paragraph("Session Timeline", st["h1"]))
        _hr(story)
        sess_rows = [["Session ID", "User", "Type", "IP", "Logon Time", "Logoff Time", "Status"]]
        for s in sessions:
            sess_rows.append([
                _safe(getattr(s, "session_id",   "")),
                _safe(getattr(s, "user",         "")),
                _safe(getattr(s, "logon_type",   "")),
                _safe(getattr(s, "ip_address",   "")),
                _safe(getattr(s, "logon_time",   "")),
                _safe(getattr(s, "logoff_time",  "") or "—"),
                _safe(getattr(s, "status",       "")),
            ])
        se_tbl = Table(sess_rows, colWidths=[22*mm, 22*mm, 28*mm, 22*mm, 32*mm, 28*mm, 20*mm])
        se_tbl.setStyle(_tbl_style())
        story.append(se_tbl)
        story.append(Spacer(1, 8))

    # ── Anti-Forensic Findings ───────────────────────────────────────────────
    if anti:
        story.append(Paragraph("Anti-Forensic Findings", st["h1"]))
        _hr(story)
        af_rows = [["Type", "Event ID", "Time", "Severity", "Evidence"]]
        for f in anti:
            af_rows.append([
                _safe(getattr(f, "finding_type", "")),
                _safe(getattr(f, "event_id",     "")),
                _safe(getattr(f, "time",         "")),
                _safe(getattr(f, "severity",     "")),
                _safe(getattr(f, "evidence",     "")),
            ])
        af_tbl = Table(af_rows, colWidths=[28*mm, 18*mm, 32*mm, 18*mm, None])
        af_tbl.setStyle(_tbl_style())
        for i, f in enumerate(anti, start=1):
            sev = str(getattr(f, "severity", "") or "").lower()
            clr = HIGH_CLR if sev == "high" else MED_CLR if sev == "medium" else LOW_CLR
            af_tbl.setStyle(TableStyle([("BACKGROUND", (3, i), (3, i), clr),
                                         ("TEXTCOLOR",  (3, i), (3, i), WHITE)]))
        story.append(af_tbl)
        story.append(Spacer(1, 8))

    # ── Event Statistics ─────────────────────────────────────────────────────
    if events:
        story.append(Paragraph("Event Statistics by Event ID", st["h1"]))
        _hr(story)
        from collections import Counter
        counts = Counter(str(getattr(e, "event_id", "?")) for e in events)
        ev_rows = [["Event ID", "Count"]] + [[eid, str(cnt)] for eid, cnt in sorted(counts.items())]
        ev_tbl = Table(ev_rows, colWidths=[60*mm, 40*mm])
        ev_tbl.setStyle(_tbl_style())
        story.append(ev_tbl)
        story.append(Spacer(1, 8))

    # ── Full Event Table ──────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Full Event Log", st["h1"]))
    _hr(story)

    ev_cols = ["Time", "Event ID", "Category", "Description", "User", "IP", "Logon Type"]
    ev_data = [ev_cols]
    for e in events:
        ev_data.append([
            _safe(getattr(e, "time_created",   "")),
            _safe(getattr(e, "event_id",       "")),
            _safe(getattr(e, "category",       "")),
            _safe(getattr(e, "description",    "")),
            _safe(getattr(e, "target_username","") or getattr(e, "user", "")),
            _safe(getattr(e, "ip_address",     "")),
            _safe(getattr(e, "logon_type",     "")),
        ])
    ev_tbl = Table(ev_data, colWidths=[30*mm, 16*mm, 25*mm, 40*mm, 22*mm, 22*mm, 22*mm],
                   repeatRows=1)
    ev_tbl.setStyle(_tbl_style())
    story.append(ev_tbl)
    story.append(Spacer(1, 8))

    # ── Chain of Custody ─────────────────────────────────────────────────────
    if data.custody:
        story.append(PageBreak())
        story.append(Paragraph("Chain of Custody", st["h1"]))
        _hr(story)
        coc = data.custody
        coc_meta = [
            ["Tool",     _safe(f"WinLogin Forensics {getattr(coc, 'tool_version', '1.0.0')}")],
            ["Operator", _safe(getattr(coc, "operator", ""))],
            ["Started",  _safe(getattr(coc, "started",  ""))],
            ["Command",  _safe(getattr(coc, "command_line", ""))],
        ]
        coc_tbl = Table(coc_meta, colWidths=[35*mm, None])
        coc_tbl.setStyle(TableStyle([
            ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 8),
            ("GRID",        (0,0), (-1,-1), 0.3, BORDER),
            ("BACKGROUND",  (0,0), (0,-1), TBL_ALT),
            ("LEFTPADDING", (0,0), (-1,-1), 5),
            ("TOPPADDING",  (0,0), (-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1),3),
        ]))
        story.append(coc_tbl)
        story.append(Spacer(1, 6))

        src_files = getattr(coc, "source_files", []) or []
        if src_files:
            story.append(Paragraph("Source Files", st["h2"]))
            sf_rows = [["File", "SHA-256"]]
            for sf in src_files:
                if isinstance(sf, dict):
                    name   = _safe(sf.get("filename", sf.get("path", "")))
                    digest = _safe(sf.get("sha256", ""))
                else:
                    name   = _safe(getattr(sf, "filename", str(sf)))
                    digest = _safe(getattr(sf, "sha256", ""))
                sf_rows.append([name, digest])
            sf_tbl = Table(sf_rows, colWidths=[60*mm, None])
            sf_tbl.setStyle(_tbl_style())
            story.append(sf_tbl)
            story.append(Spacer(1, 4))

        actions = getattr(coc, "actions", []) or []
        if actions:
            story.append(Paragraph("Actions Log", st["h2"]))
            ac_rows = [["Timestamp", "Action", "Detail"]]
            for ac in actions:
                if isinstance(ac, dict):
                    ac_rows.append([
                        _safe(ac.get("timestamp", "")),
                        _safe(ac.get("action",    "")),
                        _safe(ac.get("detail",    "")),
                    ])
                else:
                    ac_rows.append([
                        _safe(getattr(ac, "timestamp", "")),
                        _safe(getattr(ac, "action",    "")),
                        _safe(getattr(ac, "detail",    "")),
                    ])
            ac_tbl = Table(ac_rows, colWidths=[32*mm, 28*mm, None])
            ac_tbl.setStyle(_tbl_style())
            story.append(ac_tbl)

    # ── Footer note ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 12))
    _hr(story)
    story.append(Paragraph(
        "WinLogin Forensics v1.0.0 — Digital signatures provide integrity evidence; "
        "they do not constitute legal chain-of-custody under any specific jurisdiction.",
        st["label"]
    ))

    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(GREY)
        canvas.drawString(15*mm, 10*mm, "WinLogin Forensics — Forensic Analysis Report")
        canvas.drawRightString(page_w - 15*mm, 10*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(out),
        pagesize=A4,
        leftMargin=15*mm,
        rightMargin=15*mm,
        topMargin=15*mm,
        bottomMargin=22*mm,
        title="WinLogin Forensics — Forensic Analysis Report",
        author=data.case.investigator if data.case else "WinLogin Forensics",
    )
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return out


class PdfReportGenerator:
    """Convert HTML forensic reports to PDF and log the SHA-256."""

    def __init__(
        self,
        wkhtmltopdf_path: Optional[str] = None,
        pdf_options: Optional[dict] = None,
    ):
        self.config = None
        if PDFKIT_AVAILABLE and wkhtmltopdf_path:
            self.config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
        self.pdf_options = {**DEFAULT_PDF_OPTIONS, **(pdf_options or {})}

    def from_html_string(self, html: str, output_path: Union[str, Path]) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        if PDFKIT_AVAILABLE and self._wkhtmltopdf_works():
            pdfkit.from_string(html, str(out), options=self.pdf_options, configuration=self.config)
            return out
        # wkhtmltopdf not available — caller should use generate() which passes ReportData
        out.write_bytes(b"%PDF-1.4\n% no wkhtmltopdf; use generate() for structured output\n")
        return out

    def from_html_file(self, html_path: Union[str, Path], output_path: Optional[Union[str, Path]] = None) -> Path:
        html_path = Path(html_path)
        if output_path is None:
            output_path = html_path.with_suffix(".pdf")
        return self.from_html_string(html_path.read_text(encoding="utf-8"), output_path)

    def generate(
        self,
        data: ReportData,
        output_path: Union[str, Path],
        sign: bool = False,
        timestamp: bool = False,
        operator: Optional[str] = None,
        keep_html: bool = True,
        custody: Optional[ChainOfCustody] = None,
    ) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        if custody is not None and data.custody is None:
            data.custody = custody

        # Prefer wkhtmltopdf (renders the full HTML faithfully)
        if PDFKIT_AVAILABLE and self._wkhtmltopdf_works():
            html_path = out.with_suffix(".html") if keep_html else out.with_suffix(".tmp.html")
            html_gen = HtmlReportGenerator()
            html_gen.generate_html(data, output_path=html_path, sign=sign,
                                   timestamp=timestamp, operator=operator)
            pdf_path = self.from_html_file(html_path, out)
            if not keep_html and html_path.suffix == ".tmp.html":
                html_path.unlink(missing_ok=True)
        elif REPORTLAB_AVAILABLE:
            # Structured ReportLab path — reads ReportData directly
            pdf_path = _build_pdf_from_data(data, out)
        else:
            out.write_bytes(b"%PDF-1.4\n% install reportlab: pip install reportlab\n")
            pdf_path = out

        digest = hash_file(pdf_path)
        log = data.custody or custody or ChainOfCustody(operator=operator)
        log.add_output_file(pdf_path, digest)
        log.log_action("report", f"PDF generated sha256={digest}")
        log.save(pdf_path.parent / "custody_log.json")
        return pdf_path

    def _wkhtmltopdf_works(self) -> bool:
        try:
            import shutil
            return shutil.which("wkhtmltopdf") is not None or self.config is not None
        except Exception:
            return False


def generate_report_pdf(
    data: ReportData,
    output_path: Union[str, Path],
    sign: bool = False,
    timestamp: bool = False,
    wkhtmltopdf_path: Optional[str] = None,
    custody: Optional[ChainOfCustody] = None,
) -> Path:
    gen = PdfReportGenerator(wkhtmltopdf_path=wkhtmltopdf_path)
    return gen.generate(data, output_path, sign=sign, timestamp=timestamp, custody=custody)