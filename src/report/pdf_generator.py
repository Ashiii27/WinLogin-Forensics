"""WinLogin Forensics - PDF report generation."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Optional, Union

try:
    import pdfkit

    PDFKIT_AVAILABLE = True
except ImportError:  # pragma: no cover
    pdfkit = None
    PDFKIT_AVAILABLE = False

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .html_generator import HtmlReportGenerator, ReportData
from .integrity import ChainOfCustody, ReportIntegrity, hash_file, TOOL_NAME, TOOL_VERSION


class PdfReportGenerator:
    """Render a forensic report to PDF using the HTML template when possible.

    The project already ships with a Jinja2 HTML report and a PDF dependency in
    requirements.txt. If `wkhtmltopdf` is available, the HTML is converted to a
    polished PDF. Otherwise a reportlab fallback renders a simplified but valid
    PDF so the feature remains usable on machines without the external binary.
    """

    def __init__(self, wkhtmltopdf_path: Optional[str] = None):
        self.wkhtmltopdf_path = wkhtmltopdf_path

    def _render_html(self, data: ReportData, operator: Optional[str] = None, custody: Optional[ChainOfCustody] = None) -> str:
        generator = HtmlReportGenerator()
        context = generator.build_context(data)

        coc = custody or ChainOfCustody(operator=operator, parameters=data.parameters)
        for src in data.source_files:
            coc.source_files.append(src)
        context["chain_of_custody"] = coc.to_dict()

        template = generator.env.get_template("report_template.html")
        html = template.render(**context)

        integrity = ReportIntegrity(sign=False, timestamp=False)
        context["integrity"] = integrity.process(html)
        return template.render(**context)

    def _wkhtmltopdf_available(self) -> bool:
        if self.wkhtmltopdf_path:
            path = Path(self.wkhtmltopdf_path)
            return path.exists() or shutil.which(str(path)) is not None or shutil.which(self.wkhtmltopdf_path) is not None
        return shutil.which("wkhtmltopdf") is not None

    def _generate_via_pdfkit(self, html_content: str, output_path: Path) -> Path:
        if not PDFKIT_AVAILABLE:
            raise RuntimeError("pdfkit is not installed")

        options = {
            "quiet": "",
            "page-size": "Letter",
            "encoding": "UTF-8",
            "enable-local-file-access": "",
        }

        # Use pdfkit.configuration to point to the wkhtmltopdf binary when needed.
        config = None
        try:
            if self.wkhtmltopdf_path:
                # If the provided path is a file/absolute path, use it directly; otherwise try to resolve with shutil.which
                resolved = shutil.which(str(self.wkhtmltopdf_path)) or str(self.wkhtmltopdf_path)
                config = pdfkit.configuration(wkhtmltopdf=str(resolved))
            else:
                which_path = shutil.which("wkhtmltopdf")
                if which_path:
                    config = pdfkit.configuration(wkhtmltopdf=which_path)
        except Exception:
            # If configuration fails, leave config as None and let pdfkit try its default discovery.
            config = None

        # Pass the configuration object explicitly to ensure pdfkit invokes the correct binary.
        pdfkit.from_string(html_content, str(output_path), options=options, configuration=config)
        return output_path

    def _generate_fallback_reportlab(self, data: ReportData, output_path: Path) -> Path:
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "Title",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=24,
            spaceAfter=16,
            textColor=colors.HexColor("#0f2744"),
        )
        heading_style = ParagraphStyle(
            "Heading2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            spaceBefore=12,
            textColor=colors.HexColor("#0f2744"),
        )
        body_style = ParagraphStyle(
            "BodyText",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
        )

        case = data.case
        story = []
        story.append(Paragraph(f"{TOOL_NAME} — Forensic Analysis Report", title_style))
        story.append(Paragraph(f"Case: {case.case_number or 'N/A'} | Investigator: {case.investigator or 'N/A'} | Organization: {case.organization or 'N/A'}", body_style))
        story.append(Paragraph(f"Analysis date: {case.analysis_date or 'N/A'} | Hostname: {case.system_hostname or 'N/A'} | OS: {case.system_os or 'N/A'}", body_style))
        story.append(Spacer(1, 0.2 * inch))

        executive = getattr(data, "executive_summary", None)
        if executive is None:
            executive = [
                f"Analysis covered {len(data.events) if data.events is not None else 0} events.",
                f"Session correlation identified {len(data.sessions) if data.sessions is not None else 0} sessions.",
            ]
        story.append(Paragraph("Executive Summary", heading_style))
        for bullet in executive:
            story.append(Paragraph(f"• {bullet}", body_style))

        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph("Anomalies", heading_style))
        rows = [["Timestamp", "Finding", "Severity", "MITRE", "Details"]]
        for finding in data.anomalies or []:
            rows.append([
                str(finding.get("timestamp", "")),
                str(finding.get("anomaly", "Unknown")),
                str(finding.get("severity", "Unknown")),
                str(finding.get("mitre_id", "")),
                str(finding.get("details", ""))[:180],
            ])
        if len(rows) == 1:
            rows.append(["—", "No anomalies flagged.", "—", "—", "—"])
        table = Table(rows, colWidths=[0.9 * inch, 1.3 * inch, 0.8 * inch, 0.8 * inch, 2.0 * inch])
        table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f2744")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ("WORDWRAP", (0, 0), (-1, -1), True),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )
        story.append(table)
        story.append(Spacer(1, 0.2 * inch))

        if data.custody is not None:
            story.append(Paragraph("Chain of Custody", heading_style))
            story.append(Paragraph(f"Operator: {data.custody.operator} | Host: {data.custody.hostname}", body_style))
            for item in data.custody.output_files[:5]:
                story.append(Paragraph(f"Output: {item.get('filename', '')} | SHA256: {item.get('sha256', '')}", body_style))
            for action in data.custody.actions[:5]:
                story.append(Paragraph(f"{action.get('action', '')}: {action.get('detail', '')}", body_style))

        doc = SimpleDocTemplate(str(output_path), pagesize=letter, title=f"{TOOL_NAME} Report", author="WinLogin Forensics")
        doc.build(story)
        return output_path

    def generate(
        self,
        data: ReportData,
        output_path: Union[str, Path],
        operator: Optional[str] = None,
        custody: Optional[ChainOfCustody] = None,
    ) -> Path:
        """Generate a PDF report and return the output path."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        html_content = self._render_html(data, operator=operator, custody=custody)

        if self._wkhtmltopdf_available() and PDFKIT_AVAILABLE:
            try:
                self._generate_via_pdfkit(html_content, output_path)
            except Exception:
                self._generate_fallback_reportlab(data, output_path)
        else:
            self._generate_fallback_reportlab(data, output_path)

        if custody is not None:
            custody.add_output_file(output_path, hash_file(output_path))
            custody.save(output_path.parent / "custody_log.json")

        return output_path


def generate_report_pdf(
    data: ReportData,
    output_path: Union[str, Path],
    operator: Optional[str] = None,
    custody: Optional[ChainOfCustody] = None,
) -> Path:
    """Convenience function to generate and save a PDF report."""
    return PdfReportGenerator().generate(data, output_path, operator=operator, custody=custody)
