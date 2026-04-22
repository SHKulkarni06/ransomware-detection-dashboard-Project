"""
ml/anomaly_model.py
====================
Unsupervised anomaly detection using Isolation Forest.

Workflow:
  1. Collect at least MIN_SAMPLES traffic summaries (baseline learning)
  2. Call train_model(summaries) once to fit the model
  3. Call detect_anomaly(summary) for every new summary — returns True
     if the behaviour deviates significantly from the baseline

The model is also serialised to disk so it survives a dashboard restart.
"""

import os
import logging
import numpy as np
import joblib
from typing import List, Optional
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Configuration                                                        #
# ------------------------------------------------------------------ #
MIN_SAMPLES = 20                    # minimum baselines before training
MODEL_PATH = "ml/model.pkl"         # persisted model location
CONTAMINATION = 0.03                # expected fraction of anomalies

# ------------------------------------------------------------------ #
# Module state                                                         #
# ------------------------------------------------------------------ #
_model: Optional[IsolationForest] = None
_trained: bool = False


# ------------------------------------------------------------------ #
# Feature vector builder                                               #
# ------------------------------------------------------------------ #

def _to_vector(summary: dict) -> List[float]:
    """Convert a traffic summary dict into a numeric feature vector."""
    return [
        float(summary.get("packet_count", 0)),
        float(summary.get("avg_packet_size", 0)),
        float(summary.get("packet_rate", 0)),
        float(len(summary.get("protocols", []))),
    ]


# ------------------------------------------------------------------ #
# Training                                                             #
# ------------------------------------------------------------------ #

def train_model(summaries: List[dict]) -> bool:
    """
    Fit an Isolation Forest on historical traffic summaries.

    Parameters
    ----------
    summaries : list of summary dicts from feature_extractor.get_summary()

    Returns True on success, False if not enough samples.
    """
    global _model, _trained

    if len(summaries) < MIN_SAMPLES:
        logger.debug(f"Not enough samples to train: {len(summaries)}/{MIN_SAMPLES}")
        return False

    X = np.array([_to_vector(s) for s in summaries])

    _model = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        random_state=42,
        n_jobs=-1,
    )
    _model.fit(X)
    _trained = True

    # Persist model
    os.makedirs(os.path.dirname(MODEL_PATH) or ".", exist_ok=True)
    joblib.dump(_model, MODEL_PATH)

    logger.info(f"Isolation Forest trained on {len(summaries)} samples → saved to {MODEL_PATH}")
    print(f"[ML] Model trained on {len(summaries)} samples")
    return True


# ------------------------------------------------------------------ #
# Inference                                                            #
# ------------------------------------------------------------------ #

def detect_anomaly(summary: dict) -> bool:
    """
    Predict whether a traffic summary is anomalous.

    Returns True if the model classifies the behaviour as an outlier.
    Returns False if not trained yet (fail-safe).
    """
    if not _trained or _model is None:
        return False

    X = np.array([_to_vector(summary)])
    prediction = _model.predict(X)  # -1 = anomaly, 1 = normal
    return int(prediction[0]) == -1


def get_anomaly_score(summary: dict) -> float:
    """
    Return the raw anomaly score (lower = more anomalous).
    Useful for risk scoring in the dashboard.
    """
    if not _trained or _model is None:
        return 0.0
    X = np.array([_to_vector(summary)])
    # decision_function returns negative scores for anomalies
    return float(_model.decision_function(X)[0])


# ------------------------------------------------------------------ #
# Model status                                                         #
# ------------------------------------------------------------------ #

def is_trained() -> bool:
    return _trained


def load_model_from_disk() -> bool:
    """Attempt to reload a previously saved model on startup."""
    global _model, _trained
    if os.path.exists(MODEL_PATH):
        try:
            _model = joblib.load(MODEL_PATH)
            _trained = True
            logger.info(f"ML model loaded from {MODEL_PATH}")
            print(f"[ML] Pre-trained model loaded from {MODEL_PATH}")
            return True
        except Exception as exc:
            logger.warning(f"Could not load model: {exc}")
    return False