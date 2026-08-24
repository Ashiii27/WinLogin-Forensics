"""Qt desktop interface for the WinLogin Forensics analysis pipeline.

The CLI and this window intentionally use the same ``AnalysisPipeline`` and
report generators.  That keeps the desktop app useful for the same evidence
formats without maintaining a second analysis implementation.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from importlib import import_module
from pathlib import Path
from typing import Any, Dict, Optional

QtCore = import_module("PyQt6.QtCore")
QtWidgets = import_module("PyQt6.QtWidgets")
QThread = QtCore.QThread
QObject = QtCore.QObject
pyqtSignal = QtCore.pyqtSignal
QApplication = QtWidgets.QApplication
QMainWindow = QtWidgets.QMainWindow
QTableWidget = QtWidgets.QTableWidget
QTableWidgetItem = QtWidgets.QTableWidgetItem
QPushButton = QtWidgets.QPushButton
QVBoxLayout = QtWidgets.QVBoxLayout
QHBoxLayout = QtWidgets.QHBoxLayout
QFormLayout = QtWidgets.QFormLayout
QWidget = QtWidgets.QWidget
QFileDialog = QtWidgets.QFileDialog
QLineEdit = QtWidgets.QLineEdit
QComboBox = QtWidgets.QComboBox
QDoubleSpinBox = QtWidgets.QDoubleSpinBox
QTabWidget = QtWidgets.QTabWidget
QPlainTextEdit = QtWidgets.QPlainTextEdit
QLabel = QtWidgets.QLabel
QGroupBox = QtWidgets.QGroupBox
QMessageBox = QtWidgets.QMessageBox

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.pipeline import AnalysisPipeline, AnalysisResult
from src.live.live_monitor import LiveMonitor
from src.report.html_generator import CaseInfo, HtmlReportGenerator, ReportData
from src.report.pdf_generator import PdfReportGenerator


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _report_data(result: AnalysisResult, operator: str) -> ReportData:
    return ReportData(
        case=CaseInfo(case_number="QT", investigator=operator),
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


class AnalysisWorker(QObject):
    """Run one pipeline command without blocking the Qt event loop."""

    finished = pyqtSignal(object, str)
    failed = pyqtSignal(str)

    def __init__(self, action: str, settings: Dict[str, Any]):
        super().__init__()
        self.action = action
        self.settings = settings

    def run(self) -> None:
        try:
            output = Path(self.settings["output_dir"])
            output.mkdir(parents=True, exist_ok=True)
            if self.action == "acquire":
                status_file = output / f".acquisition_status_{os.getpid()}.json"
                status_file.unlink(missing_ok=True)
                command = [
                    sys.executable,
                    str(ROOT / "acquire_artifacts.py"),
                    "--output-dir",
                    str(output),
                    "--include-ntuser",
                    "--status-file",
                    str(status_file),
                ]
                completed = subprocess.run(command, capture_output=True, text=True, check=False)
                try:
                    status = json.loads(status_file.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    status = {"exit_code": completed.returncode, "message": completed.stderr.strip()}
                status_file.unlink(missing_ok=True)
                if completed.returncode != 0 or int(status.get("exit_code", 1)) != 0:
                    raise RuntimeError(status.get("message") or completed.stderr.strip() or "Artifact acquisition failed")
                self.finished.emit(status, self.action)
                return
            if self.action == "live":
                self.finished.emit(LiveMonitor().summary(), self.action)
                return

            pipeline = AnalysisPipeline(
                evtx_paths=self.settings["evtx_paths"],
                hive_dir=self.settings["hive_dir"] or None,
                sysmon_path=self.settings["sysmon_path"] or None,
                powershell_path=self.settings["powershell_path"] or None,
                output_dir=output,
                threshold=self.settings["threshold"],
                operator=self.settings["operator"] or None,
            )
            result = pipeline.run()
            if self.action in {"parse", "all"}:
                result.events.to_json(output / "events.json", orient="records", date_format="iso")
                if not result.sessions.empty:
                    result.sessions.to_json(output / "sessions.json", orient="records", date_format="iso")
                _write_json(output / "anomalies.json", result.anomalies)
            elif self.action == "correlate":
                result.sessions.to_json(output / "sessions.json", orient="records", date_format="iso")
            elif self.action == "detect":
                _write_json(output / "anomalies.json", result.anomalies)
                _write_json(output / "antiforensic.json", result.antiforensic)

            if self.action in {"parse", "report", "all"}:
                fmt = self.settings["format"]
                if self.action == "report" and fmt == "json":
                    fmt = "html"
                if fmt == "json":
                    _write_json(output / "analysis.json", {
                        "events": result.events.to_dict(orient="records"),
                        "sessions": result.sessions.to_dict(orient="records"),
                        "anomalies": result.anomalies,
                        "antiforensic": result.antiforensic,
                    })
                elif fmt == "html":
                    HtmlReportGenerator().generate_html(_report_data(result, self.settings["operator"]), output_path=output / "report.html")
                else:
                    PdfReportGenerator().generate(_report_data(result, self.settings["operator"]), output / "report.pdf", custody=result.custody)
            if result.custody:
                result.custody.save(output / "custody_log.json")
            self.finished.emit(result, self.action)
        except Exception as exc:  # surface errors in the GUI instead of killing the worker thread
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Login Forensics")
        self.setMinimumSize(1180, 720)
        self._thread: Optional[QThread] = None
        self._worker: Optional[AnalysisWorker] = None
        self.result: Optional[AnalysisResult] = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)

        inputs = QGroupBox("Evidence and analysis options")
        form = QFormLayout(inputs)
        self.evtx_edit = QLineEdit()
        self.evtx_edit.setPlaceholderText("EVTX/XML/JSON directory or files")
        evtx_row = QHBoxLayout(); evtx_row.addWidget(self.evtx_edit)
        evtx_button = QPushButton("Directory…"); evtx_button.clicked.connect(self.choose_evtx); evtx_row.addWidget(evtx_button)
        evtx_files_button = QPushButton("Files…"); evtx_files_button.clicked.connect(self.choose_evtx_files); evtx_row.addWidget(evtx_files_button)
        form.addRow("EVTX directory/files", evtx_row)
        self.hive_edit = self._path_row(form, "Registry hive directory", self.choose_hive)
        self.sysmon_edit = self._path_row(form, "Sysmon log (optional)", lambda: self.choose_file(self.sysmon_edit, "Sysmon log"))
        self.powershell_edit = self._path_row(form, "PowerShell log (optional)", lambda: self.choose_file(self.powershell_edit, "PowerShell log"))
        self.output_edit = self._path_row(form, "Output directory", self.choose_output)
        self.operator_edit = QLineEdit()
        form.addRow("Operator", self.operator_edit)
        self.threshold = QDoubleSpinBox(); self.threshold.setRange(0.0, 1.0); self.threshold.setSingleStep(0.05); self.threshold.setValue(0.5)
        form.addRow("Anomaly threshold", self.threshold)
        self.format_box = QComboBox(); self.format_box.addItems(["json", "html", "pdf"])
        form.addRow("Report format", self.format_box)
        layout.addWidget(inputs)

        actions = QHBoxLayout()
        for text, action in [("Acquire live artifacts (Admin)", "acquire"), ("Parse", "parse"), ("Correlate", "correlate"), ("Detect", "detect"), ("Generate report", "report"), ("Live monitor", "live")]:
            button = QPushButton(text); button.clicked.connect(lambda checked=False, name=action: self.run_action(name)); actions.addWidget(button)
        layout.addLayout(actions)
        self.status = QLabel("Ready. Select an evidence directory or file to begin.")
        layout.addWidget(self.status)
        self.tabs = QTabWidget()
        for name in ("Events", "Sessions", "Anomalies", "Anti-forensic", "Registry", "Live"):
            widget = QTableWidget() if name != "Live" else QPlainTextEdit()
            if isinstance(widget, QPlainTextEdit): widget.setReadOnly(True)
            self.tabs.addTab(widget, name)
        layout.addWidget(self.tabs)
        self.setCentralWidget(root)

    def _path_row(self, form: QFormLayout, label: str, callback):
        edit = QLineEdit(); row = QHBoxLayout(); row.addWidget(edit)
        button = QPushButton("Choose…"); button.clicked.connect(callback); row.addWidget(button); form.addRow(label, row)
        return edit

    def choose_evtx(self):
        path = QFileDialog.getExistingDirectory(self, "Choose EVTX directory")
        if path: self.evtx_edit.setText(path)

    def choose_evtx_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Choose EVTX/XML/JSON evidence", "",
            "Evidence files (*.evtx *.xml *.json *.csv);;All files (*)",
        )
        if paths: self.evtx_edit.setText(";".join(paths))

    def choose_hive(self):
        path = QFileDialog.getExistingDirectory(self, "Choose registry hive directory")
        if path: self.hive_edit.setText(path)

    def choose_output(self):
        path = QFileDialog.getExistingDirectory(self, "Choose output directory")
        if path: self.output_edit.setText(path)

    def choose_file(self, edit: QLineEdit, label: str):
        path, _ = QFileDialog.getOpenFileName(self, f"Choose {label}", "", "Log files (*.evtx *.xml *.json *.csv);;All files (*)")
        if path: edit.setText(path)

    def _settings(self) -> Dict[str, Any]:
        raw = self.evtx_edit.text().strip()
        paths = [Path(part.strip()) for part in raw.split(";") if part.strip()]
        return {"evtx_paths": paths, "hive_dir": self.hive_edit.text().strip(), "sysmon_path": self.sysmon_edit.text().strip(),
                "powershell_path": self.powershell_edit.text().strip(), "output_dir": self.output_edit.text().strip() or str(ROOT / "output"),
                "operator": self.operator_edit.text().strip(), "threshold": self.threshold.value(), "format": self.format_box.currentText()}

    def run_action(self, action: str):
        settings = self._settings()
        if action not in {"live", "acquire"} and not settings["evtx_paths"]:
            QMessageBox.warning(self, "Evidence required", "Choose an EVTX/XML/JSON directory or file first.")
            return
        self._set_busy(True, f"Running {action}…")
        self._thread = QThread(self); self._worker = AnalysisWorker(action, settings); self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run); self._worker.finished.connect(self._finished); self._worker.failed.connect(self._failed)
        self._worker.finished.connect(self._thread.quit); self._worker.failed.connect(self._thread.quit); self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def _set_busy(self, busy: bool, message: str):
        self.status.setText(message)
        for button in self.findChildren(QPushButton): button.setEnabled(not busy)

    def _finished(self, payload: object, action: str):
        self._set_busy(False, f"{action.capitalize()} complete. Results saved to {self._settings()['output_dir']}.")
        if action == "acquire":
            output = self._settings()["output_dir"]
            self.evtx_edit.setText(output)
            self.hive_edit.setText(output)
            self.status.setText(f"Artifacts acquired. Evidence inputs set to {output}.")
            return
        if isinstance(payload, AnalysisResult):
            self.result = payload; self._display_result(payload)
        else:
            self._live_table().setPlainText(json.dumps(payload, indent=2, default=str))

    def _failed(self, message: str):
        self._set_busy(False, "Operation failed."); QMessageBox.critical(self, "Analysis error", message)

    def _live_table(self):
        return self.tabs.widget(5)

    def _display_result(self, result: AnalysisResult):
        self._fill_table(self.tabs.widget(0), result.events)
        self._fill_table(self.tabs.widget(1), result.sessions)
        self._fill_table(self.tabs.widget(2), result.anomalies)
        self._fill_table(self.tabs.widget(3), result.antiforensic)
        registry = [{"hive": key, "records": value} for key, value in result.registry.items()]
        self._fill_table(self.tabs.widget(4), registry)

    @staticmethod
    def _fill_table(table: QTableWidget, rows: Any):
        if hasattr(rows, "to_dict"): rows = rows.to_dict(orient="records")
        rows = list(rows or [])
        columns = sorted({str(key) for row in rows if isinstance(row, dict) for key in row})
        table.clear(); table.setRowCount(len(rows)); table.setColumnCount(len(columns)); table.setHorizontalHeaderLabels(columns)
        for i, row in enumerate(rows):
            for j, column in enumerate(columns): table.setItem(i, j, QTableWidgetItem(str(row.get(column, ""))))
        table.resizeColumnsToContents()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow(); window.show()
    sys.exit(app.exec())