#!/usr/bin/env python3
"""
WinLogin Forensics - Ground-truth evaluation engine
===================================================
Ingest labeled EVTX/JSON samples (Atomic Red Team / EVTX-ATTACK-SAMPLES
style), run the session correlator + rule-based detector, and report
Precision / Recall / F1 across stratified random splits.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.anomaly_detector import AnomalyDetector
from src.parsers.evtx_parser import EvtxParser
from src.parsers.session_correlator import SessionCorrelator
from src.report.mitre_mapper import lookup_technique_id


def load_sample(path: Path) -> Dict[str, Any]:
    """
    Load a labeled sample from JSON or XML.

    Parameters
    ----------
    path : Path
        Sample file.

    Returns
    -------
    dict
        ``{name, events (DataFrame), ground_truth (list), source}``.
    """
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        events = EvtxParser().parse_records(payload.get("events", []))
        return {
            "name": payload.get("name", path.stem),
            "source": payload.get("source", "unknown"),
            "events": events,
            "ground_truth": payload.get("ground_truth", []),
        }
    events = EvtxParser(path).parse()
    # Sidecar labels if present
    sidecar = path.with_suffix(".labels.json")
    labels = []
    if sidecar.exists():
        labels = json.loads(sidecar.read_text(encoding="utf-8"))
    return {"name": path.stem, "source": "xml", "events": events, "ground_truth": labels}


def predicted_techniques(events: pd.DataFrame) -> List[str]:
    """
    Run correlator + detector and return the set of predicted technique IDs.

    Parameters
    ----------
    events : pd.DataFrame
        Sample events.

    Returns
    -------
    List[str]
        Unique MITRE IDs predicted as present.
    """
    sessions = SessionCorrelator(events).correlate()
    findings = AnomalyDetector(events, sessions).detect()
    ids = []
    for f in findings:
        tid = f.get("mitre_id") or lookup_technique_id(f.get("rule") or f.get("anomaly") or "")
        if tid and tid != "T0000":
            ids.append(tid)
    return sorted(set(ids))


def score_sample(sample: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare predicted techniques against ground-truth labels.

    Parameters
    ----------
    sample : dict
        Loaded sample.

    Returns
    -------
    dict
        Per-sample TP/FP/FN and P/R/F1.
    """
    predicted = set(predicted_techniques(sample["events"]))
    truth = set()
    for label in sample.get("ground_truth") or []:
        if not label.get("present", True):
            continue
        tid = label.get("technique_id") or lookup_technique_id(label.get("rule", ""))
        if tid:
            truth.add(tid)
    tp = predicted & truth
    fp = predicted - truth
    fn = truth - predicted
    precision = len(tp) / len(predicted) if predicted else 1.0 if not truth else 0.0
    recall = len(tp) / len(truth) if truth else 1.0
    if precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "name": sample["name"],
        "source": sample.get("source"),
        "predicted": sorted(predicted),
        "truth": sorted(truth),
        "tp": sorted(tp),
        "fp": sorted(fp),
        "fn": sorted(fn),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "session_count": int(len(SessionCorrelator(sample["events"]).correlate())),
    }


def stratified_splits(
    samples: Sequence[Dict[str, Any]],
    n_splits: int = 8,
    seed: int = 42,
) -> List[List[int]]:
    """
    Build ``n_splits`` stratified index folds (with replacement across folds
    so every sample appears in several test folds).

    Parameters
    ----------
    samples : sequence of dict
        Labeled samples.
    n_splits : int
        Number of folds (5–10 per the plan).
    seed : int
        RNG seed.

    Returns
    -------
    List[List[int]]
        Each item is a list of sample indices used as the test fold.
    """
    rng = np.random.default_rng(seed)
    # Bucket by first ground-truth technique so folds stay balanced
    buckets: Dict[str, List[int]] = {}
    for i, sample in enumerate(samples):
        labels = sample.get("ground_truth") or []
        key = "benign"
        for lab in labels:
            if lab.get("present", True) and lab.get("technique_id"):
                key = lab["technique_id"]
                break
        buckets.setdefault(key, []).append(i)

    folds: List[List[int]] = [[] for _ in range(n_splits)]
    for _, idxs in buckets.items():
        order = list(idxs)
        rng.shuffle(order)
        if not order:
            continue
        for i, idx in enumerate(order):
            folds[i % n_splits].append(idx)
        # Guarantee every fold sees at least one of this class when possible
        if len(order) < n_splits:
            extra = rng.choice(order, size=n_splits - len(order), replace=True)
            for j, idx in enumerate(extra):
                folds[(len(order) + j) % n_splits].append(int(idx))
    return folds


def evaluate(sample_dir: Path, n_splits: int = 8, seed: int = 42) -> Dict[str, Any]:
    """
    Run the full evaluation pipeline.

    Parameters
    ----------
    sample_dir : Path
        Directory of labeled JSON/XML samples.
    n_splits : int
        Number of stratified splits.
    seed : int
        RNG seed.

    Returns
    -------
    dict
        Report payload (also written to ``evaluation/results/eval_report.json``).
    """
    samples = []
    for path in sorted(sample_dir.iterdir()):
        if path.suffix.lower() not in {".json", ".xml", ".evtx"}:
            continue
        if path.name.endswith(".labels.json"):
            continue
        samples.append(load_sample(path))
    if not samples:
        raise FileNotFoundError(f"No labeled samples in {sample_dir}")

    per_sample = [score_sample(s) for s in samples]
    folds = stratified_splits(samples, n_splits=n_splits, seed=seed)
    fold_metrics = []
    for fold in folds:
        subset = [per_sample[i] for i in fold]
        fold_metrics.append(
            {
                "precision": float(np.mean([s["precision"] for s in subset])),
                "recall": float(np.mean([s["recall"] for s in subset])),
                "f1": float(np.mean([s["f1"] for s in subset])),
                "n": len(subset),
            }
        )

    def _agg(key: str) -> Dict[str, float]:
        vals = [m[key] for m in fold_metrics]
        return {"mean": float(np.mean(vals)), "std": float(np.std(vals))}

    report = {
        "n_samples": len(samples),
        "n_splits": n_splits,
        "seed": seed,
        "overall": {
            "precision": _agg("precision"),
            "recall": _agg("recall"),
            "f1": _agg("f1"),
        },
        "folds": fold_metrics,
        "per_sample": per_sample,
    }
    return report


def main(argv: Sequence[str] | None = None) -> int:
    """
    CLI entry point.

    Parameters
    ----------
    argv : sequence of str, optional
        Argument vector.

    Returns
    -------
    int
        Process exit code.
    """
    parser = argparse.ArgumentParser(description="WinLogin Forensics evaluation harness")
    parser.add_argument(
        "--sample-dir",
        type=Path,
        default=ROOT / "evaluation" / "samples",
        help="Directory of labeled samples",
    )
    parser.add_argument("--splits", type=int, default=8)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "evaluation" / "results" / "eval_report.json",
    )
    args = parser.parse_args(argv)

    report = evaluate(args.sample_dir, n_splits=args.splits, seed=args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    overall = report["overall"]
    print(
        f"F1={overall['f1']['mean']:.3f} ± {overall['f1']['std']:.3f}  "
        f"P={overall['precision']['mean']:.3f}  R={overall['recall']['mean']:.3f}  "
        f"n={report['n_samples']} splits={report['n_splits']}"
    )
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
