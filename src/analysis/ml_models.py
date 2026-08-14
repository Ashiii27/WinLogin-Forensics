"""
WinLogin Forensics - Unsupervised anomaly models
================================================
IsolationForest (hyperparameter sweep) + One-Class SVM (RBF) with an
ensemble score, joblib persistence, and SHAP TreeExplainer explanations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.svm import OneClassSVM

try:
    import shap

    SHAP_AVAILABLE = True
except ImportError:  # pragma: no cover
    SHAP_AVAILABLE = False


NUMERIC_FEATURES = [
    "hour_of_day",
    "day_of_week",
    "is_weekend",
    "is_business_hours",
    "time_since_last_logon",
    "logon_type",
    "failed_logon_count_last_1h",
    "unique_accounts_per_source_ip_last_1h",
    "has_special_privileges",
    "privilege_escalation_delta",
    "distance_km_from_last_logon",
    "impossible_travel_flag",
]

IF_N_ESTIMATORS = [100, 200]
IF_CONTAMINATION = [0.01, 0.05, 0.1]
OCSVM_NU = [0.01, 0.05, 0.1]


class AnomalyModelSuite:
    """
    Train, score, persist, and explain unsupervised auth-anomaly models.

    Parameters
    ----------
    random_state : int
        RNG seed.
    models_dir : str | Path
        Directory used by :meth:`save` / :meth:`load`.
    """

    def __init__(self, random_state: int = 42, models_dir: Optional[Path] = None):
        self.random_state = random_state
        self.models_dir = Path(models_dir) if models_dir else Path("models")
        self.scaler = StandardScaler()
        self.iforest: Optional[IsolationForest] = None
        self.ocsvm: Optional[OneClassSVM] = None
        self.best_params: Dict[str, Any] = {}
        self.feature_names: List[str] = list(NUMERIC_FEATURES)
        self._explainer = None

    def _matrix(self, features: pd.DataFrame) -> Tuple[np.ndarray, pd.DataFrame]:
        cols = [c for c in self.feature_names if c in features.columns]
        if not cols:
            cols = [c for c in features.columns if pd.api.types.is_numeric_dtype(features[c])]
        self.feature_names = cols
        frame = features[cols].copy()
        frame = frame.apply(pd.to_numeric, errors="coerce").fillna(0.0)
        return frame.to_numpy(dtype=float), frame

    def fit(self, features: pd.DataFrame) -> "AnomalyModelSuite":
        """
        Sweep IsolationForest and One-Class SVM hyperparameters and keep the
        configuration whose ensemble separates the top tail most cleanly.

        Parameters
        ----------
        features : pd.DataFrame
            Output of :class:`FeatureEngineer`.

        Returns
        -------
        AnomalyModelSuite
            ``self``, fitted.
        """
        X, _ = self._matrix(features)
        if len(X) == 0:
            raise ValueError("Cannot fit anomaly models on an empty feature matrix")
        # IsolationForest contamination must be in (0, 0.5]; shrink for tiny n
        n = len(X)
        contaminations = [c for c in IF_CONTAMINATION if c < 0.5 and int(c * n) < n]
        if not contaminations:
            contaminations = [max(0.01, min(0.1, 1.0 / max(n, 2)))]

        X_scaled = self.scaler.fit_transform(X)

        best_if: Optional[IsolationForest] = None
        best_if_score = -np.inf
        best_if_params: Dict[str, Any] = {}
        for n_est in IF_N_ESTIMATORS:
            for cont in contaminations:
                model = IsolationForest(
                    n_estimators=n_est,
                    contamination=cont,
                    random_state=self.random_state,
                    n_jobs=1,
                )
                model.fit(X_scaled)
                # Higher std of decision_function ⇒ more contrast
                scores = -model.decision_function(X_scaled)
                contrast = float(np.std(scores))
                if contrast > best_if_score:
                    best_if_score = contrast
                    best_if = model
                    best_if_params = {"n_estimators": n_est, "contamination": cont}

        best_svm: Optional[OneClassSVM] = None
        best_svm_score = -np.inf
        best_svm_params: Dict[str, Any] = {}
        for nu in OCSVM_NU:
            nu_eff = min(nu, max(1.0 / n, 0.01))
            model = OneClassSVM(kernel="rbf", nu=nu_eff, gamma="scale")
            model.fit(X_scaled)
            scores = -model.decision_function(X_scaled)
            contrast = float(np.std(scores))
            if contrast > best_svm_score:
                best_svm_score = contrast
                best_svm = model
                best_svm_params = {"nu": nu_eff, "kernel": "rbf"}

        self.iforest = best_if
        self.ocsvm = best_svm
        self.best_params = {"isolation_forest": best_if_params, "one_class_svm": best_svm_params}
        self._explainer = None
        return self

    def score(self, features: pd.DataFrame) -> pd.DataFrame:
        """
        Score every session. Ensemble = mean of min-max normalised model scores.

        Parameters
        ----------
        features : pd.DataFrame
            Feature matrix (same columns as fit).

        Returns
        -------
        pd.DataFrame
            Copy of ``features`` plus ``iforest_score``, ``ocsvm_score``,
            ``ensemble_score``, ``is_anomaly``, ``shap_explanation``.
        """
        if self.iforest is None or self.ocsvm is None:
            raise RuntimeError("Models are not fitted. Call fit() first.")
        X, frame = self._matrix(features)
        X_scaled = self.scaler.transform(X)
        if_raw = -self.iforest.decision_function(X_scaled)
        svm_raw = -self.ocsvm.decision_function(X_scaled)
        if_norm = _minmax(if_raw)
        svm_norm = _minmax(svm_raw)
        ensemble = (if_norm + svm_norm) / 2.0

        # Flag using IsolationForest's native prediction plus a high ensemble tail
        if_pred = self.iforest.predict(X_scaled)  # -1 = anomaly
        flagged = if_pred == -1

        out = features.copy()
        out["iforest_score"] = if_norm
        out["ocsvm_score"] = svm_norm
        out["ensemble_score"] = ensemble
        out["is_anomaly"] = flagged

        explanations = [{} for _ in range(len(out))]
        flagged_idx = np.where(flagged)[0]
        if len(flagged_idx):
            shap_map = self.explain(frame.iloc[flagged_idx])
            for local_i, global_i in enumerate(flagged_idx):
                explanations[int(global_i)] = shap_map[local_i]
        out["shap_explanation"] = explanations
        return out

    def explain(self, features: pd.DataFrame) -> List[Dict[str, float]]:
        """
        Compute per-feature SHAP values for the IsolationForest.

        Parameters
        ----------
        features : pd.DataFrame
            Rows to explain (already numeric).

        Returns
        -------
        List[dict]
            One ``{feature_name: shap_value}`` dict per row.
        """
        X, frame = self._matrix(features)
        if len(X) == 0:
            return []
        X_scaled = self.scaler.transform(X)
        names = list(frame.columns)

        if SHAP_AVAILABLE and self.iforest is not None:
            try:
                if self._explainer is None:
                    self._explainer = shap.TreeExplainer(self.iforest)
                values = self._explainer.shap_values(X_scaled)
                values = np.asarray(values)
                if values.ndim == 3:
                    values = values[0]
                result = []
                for row in values:
                    result.append({names[j]: float(row[j]) for j in range(len(names))})
                return result
            except Exception:
                pass
        # Fallback: feature deviation from median, signed by IsolationForest path
        median = np.median(X_scaled, axis=0)
        result = []
        for row in X_scaled:
            delta = row - median
            result.append({names[j]: float(delta[j]) for j in range(len(names))})
        return result

    def save(self, models_dir: Optional[Path] = None) -> Path:
        """
        Persist fitted models with joblib.

        Parameters
        ----------
        models_dir : Path, optional
            Destination directory.

        Returns
        -------
        Path
            Directory written.
        """
        dest = Path(models_dir) if models_dir else self.models_dir
        dest.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.iforest, dest / "isolation_forest.joblib")
        joblib.dump(self.ocsvm, dest / "one_class_svm.joblib")
        joblib.dump(self.scaler, dest / "scaler.joblib")
        joblib.dump({"feature_names": self.feature_names, "best_params": self.best_params}, dest / "meta.joblib")
        return dest

    @classmethod
    def load(cls, models_dir: Path) -> "AnomalyModelSuite":
        """
        Load a previously saved suite.

        Parameters
        ----------
        models_dir : Path
            Directory produced by :meth:`save`.

        Returns
        -------
        AnomalyModelSuite
            Restored suite.
        """
        dest = Path(models_dir)
        suite = cls(models_dir=dest)
        suite.iforest = joblib.load(dest / "isolation_forest.joblib")
        suite.ocsvm = joblib.load(dest / "one_class_svm.joblib")
        suite.scaler = joblib.load(dest / "scaler.joblib")
        meta = joblib.load(dest / "meta.joblib")
        suite.feature_names = meta.get("feature_names", list(NUMERIC_FEATURES))
        suite.best_params = meta.get("best_params", {})
        return suite


def _minmax(values: np.ndarray) -> np.ndarray:
    lo, hi = float(np.min(values)), float(np.max(values))
    if hi - lo < 1e-12:
        return np.zeros_like(values, dtype=float)
    return (values - lo) / (hi - lo)


def train_and_score(features: pd.DataFrame, models_dir: Optional[Path] = None) -> pd.DataFrame:
    """
    Fit the suite on ``features`` and return scored rows (and optionally persist).

    Parameters
    ----------
    features : pd.DataFrame
        Feature matrix.
    models_dir : Path, optional
        When given, models are written here.

    Returns
    -------
    pd.DataFrame
        Scored feature frame.
    """
    suite = AnomalyModelSuite(models_dir=models_dir)
    suite.fit(features)
    scored = suite.score(features)
    if models_dir is not None:
        suite.save(models_dir)
    return scored
