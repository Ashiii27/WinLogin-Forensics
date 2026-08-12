"""
WinLogin Forensics - PDF Report Generator
=====================================================
Exports HTML forensic reports to PDF via pdfkit (wkhtmltopdf).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

try:
    import pdfkit
    PDFKIT_AVAILABLE = True
except ImportError:
    PDFKIT_AVAILABLE = False

from .html_generator import HtmlReportGenerator, ReportData
from .integrity import hash_file


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
    """Converts HTML forensic reports to PDF format."""

    def __init__(
        self,
        wkhtmltopdf_path: Optional[str] = None,
        pdf_options: Optional[dict] = None,
    ):
        if not PDFKIT_AVAILABLE:
            raise RuntimeError(
                "pdfkit is not installed. Install with: pip install pdfkit"
            )
        self.config = None
        if wkhtmltopdf_path:
            self.config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
        self.pdf_options = {**DEFAULT_PDF_OPTIONS, **(pdf_options or {})}

    def from_html_string(
        self,
        html: str,
        output_path: Union[str, Path],
    ) -> Path:
        """Convert an HTML string to a PDF file."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        pdfkit.from_string(
            html,
            str(out),
            options=self.pdf_options,
            configuration=self.config,
        )
        return out

    def from_html_file(
        self,
        html_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
    ) -> Path:
        """Convert an existing HTML report file to PDF."""
        html_path = Path(html_path)
        if output_path is None:
            output_path = html_path.with_suffix(".pdf")
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        pdfkit.from_file(
            str(html_path),
            str(out),
            options=self.pdf_options,
            configuration=self.config,
        )
        return out

    def generate(
        self,
        data: ReportData,
        output_path: Union[str, Path],
        sign: bool = False,
        timestamp: bool = False,
        operator: Optional[str] = None,
        keep_html: bool = True,
    ) -> Path:
        """
        Generate HTML report then export to PDF.
        Optionally keeps the intermediate HTML alongside the PDF.
        """
        out = Path(output_path)
        html_path = out.with_suffix(".html") if keep_html else out.with_suffix(".tmp.html")

        html_gen = HtmlReportGenerator()
        html_gen.generate_html(
            data,
            output_path=html_path,
            sign=sign,
            timestamp=timestamp,
            operator=operator,
        )

        pdf_path = self.from_html_file(html_path, out)

        if not keep_html and html_path.suffix == ".tmp.html":
            html_path.unlink(missing_ok=True)

        return pdf_path


def generate_report_pdf(
    data: ReportData,
    output_path: Union[str, Path],
    sign: bool = False,
    timestamp: bool = False,
    wkhtmltopdf_path: Optional[str] = None,
) -> Path:
    """Convenience function to generate a PDF forensic report."""
    gen = PdfReportGenerator(wkhtmltopdf_path=wkhtmltopdf_path)
    return gen.generate(data, output_path, sign=sign, timestamp=timestamp)
