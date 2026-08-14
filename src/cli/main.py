#!/usr/bin/env python3
"""
WinLogin Forensics - Command-line interface
===========================================
Commands: parse, correlate, detect, report, live

All evidence paths come from flags — nothing is hardcoded.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.pipeline import AnalysisPipeline, AnalysisResult
from src.live.live_monitor import LiveMonitor
from src.parsers.evtx_parser import EvtxParser
from src.parsers.session_correlator import SessionCorrelator
from src.report.html_generator import CaseInfo, HtmlReportGenerator, ReportData
from src.report.pdf_generator import PdfReportGenerator


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--evtx-dir", type=Path, default=None, help="Directory of EVTX/XML/JSON logs")
    common.add_argument("--hive-dir", type=Path, default=None, help="Directory of registry hives")
    common.add_argument("--output-dir", type=Path, default=Path("output"), help="Destination directory")
    common.add_argument("--format", choices=["html", "pdf", "json"], default="json")
    common.add_argument("--threshold", type=float, default=0.5, help="Anomaly score threshold")
    common.add_argument("--operator", default=None)
    common.add_argument("--sysmon", type=Path, default=None)
    common.add_argument("--powershell", type=Path, default=None)

    parser = argparse.ArgumentParser(
        prog="winlogin",
        description="WinLogin Forensics — Windows authentication artefact analysis",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("parse", help="Parse evidence files", parents=[common])
    sub.add_parser("correlate", help="Reconstruct sessions", parents=[common])
    sub.add_parser("detect", help="Run detectors + ML", parents=[common])
    sub.add_parser("report", help="Generate HTML/PDF report", parents=[common])
    live = sub.add_parser("live", help="Live monitoring (mock queue or Windows)", parents=[common])
    live.add_argument("--alert-email", default=None)
    return parser


def _pipeline_from_args(args: argparse.Namespace) -> AnalysisPipeline:
    evtx_paths = [args.evtx_dir] if args.evtx_dir else []
    args.output_dir.mkdir(parents=True, exist_ok=True)
    return AnalysisPipeline(
        evtx_paths=evtx_paths,
        hive_dir=args.hive_dir,
        sysmon_path=args.sysmon,
        powershell_path=args.powershell,
        output_dir=args.output_dir,
        threshold=args.threshold,
        operator=args.operator,
    )


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _result_to_report_data(result: AnalysisResult) -> ReportData:
    return ReportData(
        case=CaseInfo(case_number="CLI", investigator=result.custody.operator if result.custody else ""),
        events=result.events,
        sessions=result.sessions,
        anomalies=result.anomalies,
        antiforensic=result.antiforensic,
        registry=result.registry,
        ml_results=result.ml_params,
        custody=result.custody,
        source_files=result.custody.source_files if result.custody else [],
        parameters=result.custody.parameters if result.custody else {},
    )


def _emit_report(result: AnalysisResult, output_dir: Path, fmt: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    data = _result_to_report_data(result)
    if fmt == "json":
        _write_json(
            output_dir / "analysis.json",
            {
                "events": result.events.to_dict(orient="records"),
                "sessions": result.sessions.to_dict(orient="records"),
                "anomalies": result.anomalies,
                "antiforensic": result.antiforensic,
            },
        )
        print(f"Report written to {output_dir / 'analysis.json'}")
        return
    if fmt == "html":
        try:
            html_path = output_dir / "report.html"
            HtmlReportGenerator().generate_html(data, output_path=html_path)
            print(f"HTML report written to {html_path}")
        except Exception as e:
            print(f"Error generating HTML report: {e}", file=sys.stderr)
            raise
        return
    if fmt == "pdf":
        try:
            pdf_path = output_dir / "report.pdf"
            PdfReportGenerator().generate(data, pdf_path, custody=result.custody)
            print(f"PDF report written to {pdf_path}")
        except Exception as e:
            print(f"Error generating PDF report: {e}", file=sys.stderr)
            raise
        return


def cmd_parse(args: argparse.Namespace) -> int:
    """Parse evidence and optionally produce a report (used by the final verifier)."""
    if args.evtx_dir is None:
        print("--evtx-dir is required", file=sys.stderr)
        return 2
    pipe = _pipeline_from_args(args)
    # Always run the full stack so --format pdf works from `parse`
    result = pipe.run()
    result.events.to_json(args.output_dir / "events.json", orient="records", date_format="iso")
    if not result.sessions.empty:
        result.sessions.to_json(args.output_dir / "sessions.json", orient="records", date_format="iso")
    _write_json(args.output_dir / "anomalies.json", result.anomalies)
    _emit_report(result, args.output_dir, args.format)
    if result.custody:
        result.custody.save(args.output_dir / "custody_log.json")
    print(f"Parsed {len(result.events)} events → {args.output_dir}")
    return 0


def cmd_correlate(args: argparse.Namespace) -> int:
    pipe = _pipeline_from_args(args)
    result = pipe.run()
    result.sessions.to_json(args.output_dir / "sessions.json", orient="records", date_format="iso")
    print(f"Correlated {len(result.sessions)} sessions")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    pipe = _pipeline_from_args(args)
    result = pipe.run()
    _write_json(args.output_dir / "anomalies.json", result.anomalies)
    _write_json(args.output_dir / "antiforensic.json", result.antiforensic)
    print(f"Findings: {len(result.anomalies)} anomalies, {len(result.antiforensic)} anti-forensic")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    pipe = _pipeline_from_args(args)
    result = pipe.run()
    fmt = args.format if args.format != "json" else "html"
    _emit_report(result, args.output_dir, fmt)
    if result.custody:
        result.custody.save(args.output_dir / "custody_log.json")
    return 0


def cmd_live(args: argparse.Namespace) -> int:
    monitor = LiveMonitor()
    print(monitor.summary())
    print("Live monitor initialised. Provide a queue via the Python API or run on Windows.")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    """
    CLI entry point.

    Parameters
    ----------
    argv : sequence of str, optional
        Argument vector. When the first token is a flag rather than a
        subcommand, ``parse`` is assumed so
        ``python src/cli/main.py parse --evtx-dir ...`` and
        ``python src/cli/main.py --evtx-dir ...`` both work.

    Returns
    -------
    int
        Process exit code.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    # Allow `python src/cli/main.py --evtx-dir X` (implicit parse)
    commands = {"parse", "correlate", "detect", "report", "live"}
    if argv and argv[0] not in commands and argv[0].startswith("-"):
        argv = ["parse"] + argv
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    dispatch = {
        "parse": cmd_parse,
        "correlate": cmd_correlate,
        "detect": cmd_detect,
        "report": cmd_report,
        "live": cmd_live,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
