"""
WinLogin Forensics - End-to-end analysis pipeline
=================================================
Orchestrates parse → correlate → detect → feature/ML → report for the
CLI and the Streamlit UI. Initialises the chain-of-custody log first
and writes it last.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd

from ..parsers.antiforensic_detector import AntiForensicDetector
from ..parsers.evtx_parser import EvtxParser, parse_evtx
from ..parsers.powershell_parser import PowerShellParser
from ..parsers.registry_parser import RegistryParser
from ..parsers.session_correlator import SessionCorrelator
from ..parsers.sysmon_parser import SysmonParser
from ..report.integrity import ChainOfCustody
from ..report.mitre_mapper import build_coverage_matrix, coverage_summary
from .anomaly_detector import AnomalyDetector
from .auth_graph import AuthGraphAnalyzer
from .correlator import ActivityCorrelator
from .feature_engineer import FeatureEngineer
from .ml_models import AnomalyModelSuite
from .statistics import event_summary, session_summary, severity_counts


@dataclass
class AnalysisResult:
    """Container for every artefact produced by a pipeline run."""

    events: pd.DataFrame = field(default_factory=pd.DataFrame)
    sessions: pd.DataFrame = field(default_factory=pd.DataFrame)
    enriched_sessions: pd.DataFrame = field(default_factory=pd.DataFrame)
    features: pd.DataFrame = field(default_factory=pd.DataFrame)
    scored: pd.DataFrame = field(default_factory=pd.DataFrame)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    antiforensic: List[Dict[str, Any]] = field(default_factory=list)
    graph_findings: List[Dict[str, Any]] = field(default_factory=list)
    mitre_matrix: List[Dict[str, Any]] = field(default_factory=list)
    mitre_stats: Dict[str, Any] = field(default_factory=dict)
    registry: Dict[str, Any] = field(default_factory=dict)
    sysmon: pd.DataFrame = field(default_factory=pd.DataFrame)
    powershell: pd.DataFrame = field(default_factory=pd.DataFrame)
    custody: Optional[ChainOfCustody] = None
    event_stats: Dict[str, Any] = field(default_factory=dict)
    session_stats: Dict[str, Any] = field(default_factory=dict)
    severity: Dict[str, int] = field(default_factory=dict)
    ml_params: Dict[str, Any] = field(default_factory=dict)


class AnalysisPipeline:
    """
    Run the full WinLogin Forensics analysis stack.

    Parameters
    ----------
    evtx_paths : list of paths, optional
        EVTX / XML / JSON evidence files or directories.
    hive_dir : path, optional
        Directory of registry hives / JSON fixtures.
    sysmon_path, powershell_path : path, optional
        Optional host-activity logs.
    output_dir : path, optional
        Destination for custody log / models.
    threshold : float
        Reserved for future score cut-offs.
    operator : str, optional
        Examiner name recorded in the custody log.
    events, sysmon, powershell, registry : optional
        Pre-parsed inputs (used by the demo loader and tests).
    """

    def __init__(
        self,
        evtx_paths: Optional[List[Union[str, Path]]] = None,
        hive_dir: Optional[Union[str, Path]] = None,
        sysmon_path: Optional[Union[str, Path]] = None,
        powershell_path: Optional[Union[str, Path]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        threshold: float = 0.5,
        operator: Optional[str] = None,
        events: Optional[pd.DataFrame] = None,
        sysmon: Optional[pd.DataFrame] = None,
        powershell: Optional[pd.DataFrame] = None,
        registry: Optional[Dict[str, Any]] = None,
    ):
        self.evtx_paths = [Path(p) for p in (evtx_paths or [])]
        self.hive_dir = Path(hive_dir) if hive_dir else None
        self.sysmon_path = Path(sysmon_path) if sysmon_path else None
        self.powershell_path = Path(powershell_path) if powershell_path else None
        self.output_dir = Path(output_dir) if output_dir else None
        self.threshold = float(threshold)
        self.pre_events = events
        self.pre_sysmon = sysmon
        self.pre_powershell = powershell
        self.pre_registry = registry
        custody_path = (self.output_dir / "custody_log.json") if self.output_dir else None
        self.custody = ChainOfCustody(
            operator=operator,
            parameters={"threshold": self.threshold, "evtx_paths": [str(p) for p in self.evtx_paths]},
            output_path=custody_path,
        )

    def run(self) -> AnalysisResult:
        """
        Execute every analysis stage.

        Returns
        -------
        AnalysisResult
            Fully populated result object.
        """
        events = self._parse_events()
        self.custody.log_action("parse", f"{len(events)} events")
        sysmon = self._parse_sysmon()
        powershell = self._parse_powershell()
        registry = self._parse_registry()

        sessions = SessionCorrelator(events).correlate()
        self.custody.log_action("correlate", f"{len(sessions)} sessions")

        enriched = ActivityCorrelator(sessions, sysmon=sysmon, powershell=powershell).correlate()

        rule_findings = AnomalyDetector(events, sessions).detect()
        anti = AntiForensicDetector(events, sam_records=registry.get("sam") or []).run_all()

        features = FeatureEngineer(sessions, events).transform()
        scored = pd.DataFrame()
        ml_params: Dict[str, Any] = {}
        if not features.empty and len(features) >= 8:
            try:
                suite = AnomalyModelSuite(models_dir=(self.output_dir / "models") if self.output_dir else Path("models"))
                suite.fit(features)
                scored = suite.score(features)
                ml_params = suite.best_params
                if self.output_dir:
                    suite.save(self.output_dir / "models")
                # Promote ML-flagged rows into the anomaly list
                for _, row in scored[scored["is_anomaly"] == True].iterrows():  # noqa: E712
                    rule_findings.append(
                        {
                            "anomaly": "ML ensemble anomaly",
                            "severity": "Medium",
                            "mitre_id": "T1078",
                            "timestamp": None,
                            "details": f"Session {row.get('SessionID')} ensemble={row.get('ensemble_score', 0):.3f}",
                            "confidence": float(row.get("ensemble_score", 0) or 0),
                            "shap_explanation": row.get("shap_explanation") or {},
                            "event_id": 4624,
                        }
                    )
            except Exception as exc:
                self.custody.log_action("detect", f"ML skipped: {exc}")

        graph_findings: List[Dict[str, Any]] = []
        if not sessions.empty:
            try:
                analyzer = AuthGraphAnalyzer(sessions)
                analyzer.build()
                analyzer.embed()
                graph_findings = analyzer.flag_lateral_movement()
            except Exception:
                graph_findings = []

        all_findings = list(rule_findings) + list(anti) + list(graph_findings)
        self.custody.log_action("detect", f"{len(all_findings)} findings")

        result = AnalysisResult(
            events=events,
            sessions=sessions,
            enriched_sessions=enriched,
            features=features,
            scored=scored,
            anomalies=rule_findings,
            antiforensic=anti,
            graph_findings=graph_findings,
            mitre_matrix=build_coverage_matrix(all_findings),
            mitre_stats=coverage_summary(all_findings),
            registry=registry,
            sysmon=sysmon,
            powershell=powershell,
            custody=self.custody,
            event_stats=event_summary(events),
            session_stats=session_summary(sessions),
            severity=severity_counts(all_findings),
            ml_params=ml_params,
        )
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self.custody.save(self.output_dir / "custody_log.json")
        return result

    # ------------------------------------------------------------------

    def _parse_events(self) -> pd.DataFrame:
        if self.pre_events is not None:
            return self.pre_events
        frames = []
        parser = EvtxParser(include_unsupported=True)
        for path in self.evtx_paths:
            try:
                if path.is_dir():
                    for child in path.rglob("*"):
                        if not child.is_file():
                            continue
                        if child.suffix.lower() not in {".xml", ".json", ".csv", ".evtx"}:
                            continue
                        if not _looks_like_event_log(child):
                            continue
                        self.custody.add_source_file(child)
                        try:
                            frames.append(parse_evtx(child, include_unsupported=True))
                        except Exception as exc:
                            self.custody.log_action("parse", f"failed {child}: {exc}")
                elif path.is_file():
                    self.custody.add_source_file(path)
                    frames.append(parse_evtx(path, include_unsupported=True))
            except Exception as exc:
                self.custody.log_action("parse", f"failed {path}: {exc}")
        if not frames:
            return EvtxParser()._empty_frame()
        return EvtxParser()._normalize_dataframe(pd.concat(frames, ignore_index=True))

    def _parse_sysmon(self) -> pd.DataFrame:
        if self.pre_sysmon is not None:
            return self.pre_sysmon
        if self.sysmon_path and self.sysmon_path.exists():
            self.custody.add_source_file(self.sysmon_path)
            return SysmonParser(self.sysmon_path).parse()
        # Discover under evtx dirs
        for path in self.evtx_paths:
            if path.is_dir():
                for child in path.rglob("*sysmon*"):
                    if child.suffix.lower() in {".json", ".xml", ".evtx", ".csv"}:
                        return SysmonParser(child).parse()
        return SysmonParser().parse()

    def _parse_powershell(self) -> pd.DataFrame:
        if self.pre_powershell is not None:
            return self.pre_powershell
        if self.powershell_path and self.powershell_path.exists():
            self.custody.add_source_file(self.powershell_path)
            return PowerShellParser(self.powershell_path).parse()
        for path in self.evtx_paths:
            if path.is_dir():
                for child in path.rglob("*ps*") :
                    if child.suffix.lower() in {".json", ".xml", ".evtx", ".csv"} and (
                        "powershell" in child.as_posix().lower() or child.name.startswith("ps_")
                    ):
                        return PowerShellParser(child).parse()
        return PowerShellParser().parse()

    def _parse_registry(self) -> Dict[str, Any]:
        if self.pre_registry is not None:
            return self.pre_registry
        result = {"sam": [], "run_keys": [], "remote_access": [], "userassist": []}
        search_roots = []
        if self.hive_dir and self.hive_dir.exists():
            search_roots.append(self.hive_dir)
        for path in self.evtx_paths:
            if path.is_dir():
                search_roots.append(path)
        for root in search_roots:
            for child in root.rglob("*"):
                if not child.is_file():
                    continue
                name = child.name.lower()
                parser = RegistryParser(child)
                if "sam" in name:
                    result["sam"] = parser.parse_sam()
                    self.custody.add_source_file(child)
                elif "run" in name:
                    result["run_keys"] = parser.parse_run_keys()
                    result["remote_access"] = parser.parse_remote_access_tools()
                elif "userassist" in name or "ntuser" in name:
                    result["userassist"] = parser.parse_userassist()
        return result


def _looks_like_event_log(path: Path) -> bool:
    """Return True if ``path`` is likely an EVTX/XML/JSON event export."""
    posix = path.as_posix().lower()
    name = path.name.lower()
    if any(token in posix for token in ("/registry/", "sam_accounts", "userassist", "run_keys")):
        return False
    if "sysmon" in name:
        return False
    if name.startswith("ps_") or "powershell" in posix:
        return False
    return True
