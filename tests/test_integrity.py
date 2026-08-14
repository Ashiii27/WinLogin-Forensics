"""Phase 6 — Read-only enforcement and chain-of-custody tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.report.integrity import (
    CRYPTO_AVAILABLE,
    ChainOfCustody,
    ReportIntegrity,
    compute_sha256,
    generate_rsa_key,
    hash_file,
    sign_bytes_pss,
)
from src.utils.safe_reader import (
    EvidenceTamperedError,
    EvidenceWriteAttemptError,
    ReadOnlyEvidenceFile,
    open_evidence,
)


def test_safe_reader_aborts_on_write_mode(tmp_path: Path):
    evidence = tmp_path / "Security.evtx"
    evidence.write_bytes(b"dummy-evidence")
    with pytest.raises(EvidenceWriteAttemptError):
        ReadOnlyEvidenceFile(evidence, mode="wb")
    with pytest.raises(EvidenceWriteAttemptError):
        open_evidence(evidence, mode="a+")


def test_safe_reader_write_method_aborts(tmp_path: Path):
    evidence = tmp_path / "SAM"
    evidence.write_bytes(b"hive")
    with ReadOnlyEvidenceFile(evidence, mode="rb") as handle:
        with pytest.raises(EvidenceWriteAttemptError):
            handle.write(b"tamper")
        with pytest.raises(EvidenceWriteAttemptError):
            handle.truncate(0)


def test_safe_reader_detects_hash_change(tmp_path: Path):
    evidence = tmp_path / "System.evtx"
    evidence.write_bytes(b"original-bytes")
    wrapper = ReadOnlyEvidenceFile(evidence, mode="rb")
    wrapper.__enter__()
    evidence.write_bytes(b"tampered-bytes")
    with pytest.raises(EvidenceTamperedError):
        wrapper.close()


def test_chain_of_custody_populated(tmp_path: Path):
    ev = tmp_path / "Security.xml"
    ev.write_text("<Event/>", encoding="utf-8")
    coc = ChainOfCustody(operator="examiner", parameters={"threshold": 0.5}, output_path=tmp_path)
    coc.add_source_file(ev)
    coc.log_action("parse", "parsed Security.xml")
    coc.log_action("correlate", "sessions built")
    coc.log_action("detect", "anomalies scored")
    path = coc.save(tmp_path / "custody_log.json")
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["operator"] == "examiner"
    assert payload["hostname"]
    assert payload["command_line"] is not None
    assert payload["source_files"]
    assert payload["source_files"][0]["sha256"] == hash_file(ev)
    actions = {a["action"] for a in payload["actions"]}
    assert {"startup", "parse", "correlate", "detect", "shutdown"} <= actions


@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography not installed")
def test_pss_signing_roundtrip(tmp_path: Path):
    key = generate_rsa_key(tmp_path / "operator.pem")
    integrity = ReportIntegrity(sign=True, private_key=key)
    block = integrity.process(b"report-bytes")
    assert block["signed"] is True
    assert block["sha256"] == compute_sha256(b"report-bytes")
    assert block["signature"]
    # Also exercise the helper
    sig = sign_bytes_pss(b"hello", key)
    assert isinstance(sig, str) and len(sig) > 20
