"""
WinLogin Forensics - Report Generation Package
=====================================================
HTML and PDF forensic report generation with MITRE ATT&CK mapping,
chain-of-custody logging, and report integrity (SHA-256, signing, RFC 3161).
"""

from .mitre_mapper import (
    MITRE_TECHNIQUES,
    DETECTION_TO_MITRE,
    lookup_technique,
    resolve_mitre_id,
    build_coverage_matrix,
    coverage_summary,
)
from .integrity import (
    ChainOfCustody,
    ReportIntegrity,
    compute_sha256,
    hash_file,
    TOOL_NAME,
    TOOL_VERSION,
    DEFAULT_TSA_URL,
    utc_now_iso,
)
from .html_generator import (
    CaseInfo,
    ReportData,
    HtmlReportGenerator,
    generate_report_html,
)
from .pdf_generator import (
    PdfReportGenerator,
    generate_report_pdf,
    PDFKIT_AVAILABLE,
)

__all__ = [
    # MITRE
    "MITRE_TECHNIQUES",
    "DETECTION_TO_MITRE",
    "lookup_technique",
    "resolve_mitre_id",
    "build_coverage_matrix",
    "coverage_summary",
    # Integrity
    "ChainOfCustody",
    "ReportIntegrity",
    "compute_sha256",
    "hash_file",
    "TOOL_NAME",
    "TOOL_VERSION",
    "DEFAULT_TSA_URL",
    "utc_now_iso",
    # HTML
    "CaseInfo",
    "ReportData",
    "HtmlReportGenerator",
    "generate_report_html",
    # PDF
    "PdfReportGenerator",
    "generate_report_pdf",
    "PDFKIT_AVAILABLE",
]
