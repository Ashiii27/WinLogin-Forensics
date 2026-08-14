"""WinLogin Forensics - Analysis package."""

from .anomaly_detector import AnomalyDetector, detect_anomalies
from .correlator import ActivityCorrelator, enrich_sessions
from .feature_engineer import FeatureEngineer, engineer_features
from .ml_models import AnomalyModelSuite, train_and_score
from .pipeline import AnalysisPipeline, AnalysisResult

__all__ = [
    "AnomalyDetector",
    "detect_anomalies",
    "ActivityCorrelator",
    "enrich_sessions",
    "FeatureEngineer",
    "engineer_features",
    "AnomalyModelSuite",
    "train_and_score",
    "AnalysisPipeline",
    "AnalysisResult",
]
