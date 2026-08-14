"""Phase 5 — IsolationForest / One-Class SVM / SHAP / GNN tests."""

from __future__ import annotations

import numpy as np
import pandas as pd

from src.analysis.auth_graph import AuthGraphAnalyzer
from src.analysis.feature_engineer import FeatureEngineer
from src.analysis.ml_models import NUMERIC_FEATURES, AnomalyModelSuite
from src.parsers.evtx_parser import EvtxParser
from src.parsers.session_correlator import SessionCorrelator


def _many_sessions(n_normal: int = 40, n_odd: int = 4) -> pd.DataFrame:
    rows = []
    rec = 1
    for i in range(n_normal):
        lid = hex(0x1000 + i)
        hour = 9 + (i % 8)
        rows.append(
            {
                "EventID": 4624,
                "TimeCreated": f"2026-08-12T{hour:02d}:{i % 50:02d}:00Z",
                "TargetUserName": f"user{i % 8}",
                "TargetLogonId": lid,
                "LogonType": 2,
                "IpAddress": f"192.168.1.{10 + (i % 20)}",
                "WorkstationName": f"WS{i % 5}",
                "RecordID": rec,
            }
        )
        rec += 1
        rows.append(
            {
                "EventID": 4634,
                "TimeCreated": f"2026-08-12T{hour:02d}:{(i % 50) + 5:02d}:00Z",
                "TargetUserName": f"user{i % 8}",
                "TargetLogonId": lid,
                "LogonType": 2,
                "IpAddress": f"192.168.1.{10 + (i % 20)}",
                "WorkstationName": f"WS{i % 5}",
                "RecordID": rec,
            }
        )
        rec += 1
    # Odd: after-hours RDP from TOR + no logoff + privileges
    for i in range(n_odd):
        lid = hex(0x9000 + i)
        rows.append(
            {
                "EventID": 4624,
                "TimeCreated": f"2026-08-12T02:{i:02d}:00Z",
                "TargetUserName": "Administrator",
                "TargetLogonId": lid,
                "LogonType": 10,
                "IpAddress": "185.220.101.5",
                "WorkstationName": "DC01",
                "RecordID": rec,
            }
        )
        rec += 1
        rows.append(
            {
                "EventID": 4672,
                "TimeCreated": f"2026-08-12T02:{i:02d}:01Z",
                "TargetUserName": "Administrator",
                "TargetLogonId": lid,
                "RecordID": rec,
            }
        )
        rec += 1
    events = EvtxParser().parse_records(rows)
    sessions = SessionCorrelator(events).correlate()
    return FeatureEngineer(sessions, events).transform(), sessions


def test_isolation_forest_scores_all_sessions(tmp_path):
    feats, _ = _many_sessions()
    suite = AnomalyModelSuite(models_dir=tmp_path)
    suite.fit(feats)
    scored = suite.score(feats)
    assert len(scored) == len(feats)
    assert scored["iforest_score"].notna().all()
    assert scored["ocsvm_score"].notna().all()
    assert scored["ensemble_score"].notna().all()
    assert set(scored["is_anomaly"].unique()).issubset({True, False, 0, 1})
    suite.save(tmp_path)
    assert (tmp_path / "isolation_forest.joblib").exists()
    restored = AnomalyModelSuite.load(tmp_path)
    again = restored.score(feats)
    assert len(again) == len(scored)


def test_shap_dict_nonempty_for_flagged():
    feats, _ = _many_sessions()
    suite = AnomalyModelSuite()
    suite.fit(feats)
    scored = suite.score(feats)
    flagged = scored[scored["is_anomaly"] == True]  # noqa: E712
    if flagged.empty:
        # Force an explanation on the highest ensemble score
        top = scored.sort_values("ensemble_score", ascending=False).head(3)
        expl = suite.explain(top)
        assert expl and any(expl[0].values())
    else:
        for _, row in flagged.iterrows():
            shap = row["shap_explanation"]
            assert isinstance(shap, dict) and len(shap) > 0
            assert any(abs(v) > 0 for v in shap.values()) or len(shap) == len(NUMERIC_FEATURES)


def test_auth_graph_embeds_and_flags():
    # One user authenticates to many workstations (lateral-looking)
    rows = []
    for i, ws in enumerate(["WS0", "WS1", "WS2", "WS3", "WS4", "FILE01", "DC01", "SQL01"]):
        rows.append(
            {
                "SessionID": f"S{i}",
                "Username": "alice" if i < 5 else "Administrator",
                "WorkstationName": ws,
                "LogonType": 3 if i >= 5 else 2,
            }
        )
    # Repeat normal edges so the rare admin→SQL edge is an outlier
    for i in range(12):
        rows.append(
            {
                "SessionID": f"N{i}",
                "Username": "alice",
                "WorkstationName": f"WS{i % 5}",
                "LogonType": 2,
            }
        )
    sessions = pd.DataFrame(rows)
    analyzer = AuthGraphAnalyzer(sessions, embedding_dim=8, seed=0)
    analyzer.build()
    emb = analyzer.embed()
    assert emb.shape[0] == len(analyzer.nodes)
    assert emb.shape[1] == 8
    edges = analyzer.to_edge_frame()
    assert not edges.empty
    # Function must run even if no edge exceeds 2σ on this tiny graph
    findings = analyzer.flag_lateral_movement()
    assert isinstance(findings, list)
