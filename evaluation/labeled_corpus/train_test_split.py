#!/usr/bin/env python3
"""
Reproducible train/test split for the labeled evaluation corpus.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

import numpy as np


def split_files(files: List[Path], test_size: float = 0.3, seed: int = 42) -> dict:
    """
    Split a list of sample paths into train and test sets.

    Parameters
    ----------
    files : list of Path
        Sample files.
    test_size : float
        Fraction assigned to the held-out test set.
    seed : int
        RNG seed.

    Returns
    -------
    dict
        ``{train: [...], test: [...], seed, test_size}``.
    """
    rng = np.random.default_rng(seed)
    order = np.array(sorted(str(p) for p in files))
    rng.shuffle(order)
    n_test = max(1, int(round(len(order) * test_size)))
    return {
        "seed": seed,
        "test_size": test_size,
        "test": order[:n_test].tolist(),
        "train": order[n_test:].tolist(),
    }


def main() -> int:
    """CLI entry point. Returns process exit code."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("evaluation/labeled_corpus/split.json"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.3)
    args = parser.parse_args()
    files = [p for p in args.sample_dir.iterdir() if p.suffix.lower() in {".json", ".xml", ".evtx"}]
    payload = split_files(files, test_size=args.test_size, seed=args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"train={len(payload['train'])} test={len(payload['test'])} -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
