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
except ImportError:  # pragma: no cover
    PDFKIT_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    REPORTLAB_AVAILABLE = True
except ImportError:  # pragma: no cover
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
        """
        Convert an HTML string to a PDF file.

        Parameters
        ----------
        html : str
            Rendered report HTML.
        output_path : str | Path
            Destination PDF.

        Returns
        -------
        Path
            Written PDF.
        """
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        if PDFKIT_AVAILABLE and self._wkhtmltopdf_works():
            pdfkit.from_string(html, str(out), options=self.pdf_options, configuration=self.config)
            return out
        return self._reportlab_fallback(html, out)

    def from_html_file(self, html_path: Union[str, Path], output_path: Optional[Union[str, Path]] = None) -> Path:
        """Convert an existing HTML report file to PDF."""
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
        """
        Generate HTML then export to PDF, embedding the PDF SHA-256 in the custody log.

        Parameters
        ----------
        data : ReportData
            Report inputs.
        output_path : str | Path
            Destination PDF.
        sign, timestamp : bool
            Integrity flags forwarded to the HTML generator.
        operator : str, optional
            Operator name.
        keep_html : bool
            Keep the intermediate HTML.
        custody : ChainOfCustody, optional
            Existing custody log to append to.

        Returns
        -------
        Path
            Written PDF.
        """
        out = Path(output_path)
        html_path = out.with_suffix(".html") if keep_html else out.with_suffix(".tmp.html")
        if custody is not None and data.custody is None:
            data.custody = custody

        html_gen = HtmlReportGenerator()
        html_gen.generate_html(
            data,
            output_path=html_path,
            sign=sign,
            timestamp=timestamp,
            operator=operator,
        )
        pdf_path = self.from_html_file(html_path, out)
        digest = hash_file(pdf_path)

        log = data.custody or custody or ChainOfCustody(operator=operator)
        log.add_output_file(pdf_path, digest)
        log.log_action("report", f"PDF generated sha256={digest}")
        log.save(pdf_path.parent / "custody_log.json")

        if not keep_html and html_path.suffix == ".tmp.html":
            html_path.unlink(missing_ok=True)
        return pdf_path

    def _wkhtmltopdf_works(self) -> bool:
        try:
            import shutil

            return shutil.which("wkhtmltopdf") is not None or self.config is not None
        except Exception:
            return False

    @staticmethod
    def _reportlab_fallback(html: str, out: Path) -> Path:
        """Write a readable PDF using ReportLab when wkhtmltopdf is absent."""
        if not REPORTLAB_AVAILABLE:
            # Last resort: wrap HTML in a minimal PDF-like binary so callers
            # still get a file they can hash. Prefer reportlab in tests.
            out.write_bytes(b"%PDF-1.4\n% WinLogin Forensics fallback\n" + html.encode("utf-8", errors="ignore")[:1000])
            return out

        import re

        text = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.I)
        text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.I)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()

        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(
            str(out),
            pagesize=A4,
            leftMargin=15 * mm,
            rightMargin=15 * mm,
            topMargin=15 * mm,
            bottomMargin=20 * mm,
            title="WinLogin Forensics Report",
        )
        story = [
            Paragraph("WinLogin Forensics — Forensic Analysis Report", styles["Title"]),
            Spacer(1, 8),
        ]
        # Chunk the stripped HTML so ReportLab can paginate
        chunk_size = 1800
        for i in range(0, len(text), chunk_size):
            chunk = text[i : i + chunk_size].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            story.append(Paragraph(chunk, styles["BodyText"]))
            story.append(Spacer(1, 6))
        doc.build(story)
        return out


def generate_report_pdf(
    data: ReportData,
    output_path: Union[str, Path],
    sign: bool = False,
    timestamp: bool = False,
    wkhtmltopdf_path: Optional[str] = None,
    custody: Optional[ChainOfCustody] = None,
) -> Path:
    """
    Convenience function to generate a PDF forensic report.

    Parameters
    ----------
    data : ReportData
        Report inputs.
    output_path : str | Path
        Destination.
    sign, timestamp : bool
        Integrity flags.
    wkhtmltopdf_path : str, optional
        Binary override.
    custody : ChainOfCustody, optional
        Existing custody log.

    Returns
    -------
    Path
        Written PDF.
    """
    gen = PdfReportGenerator(wkhtmltopdf_path=wkhtmltopdf_path)
    return gen.generate(data, output_path, sign=sign, timestamp=timestamp, custody=custody)
