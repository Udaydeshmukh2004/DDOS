"""
Model Updater and Candidate Validator for Adaptive Learning.

Trains candidate models on verified sample buffers + historical anchor baselines
(to prevent catastrophic forgetting), evaluates candidates against fixed validation sets,
and enforces safety criteria before candidate promotion.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from ml_models.feature_builder import FEATURE_NAMES

logger = logging.getLogger("intellishield.adaptive_learning.model_updater")

N_FEATURES = len(FEATURE_NAMES)  # 15


def _generate_synthetic_anchor_baseline(n_samples: int = 100) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate anchor baseline to mix with new verified samples to prevent catastrophic forgetting.
    """
    rng = np.random.RandomState(42)
    n_norm = int(n_samples * 0.6)
    n_atk = n_samples - n_norm

    X_norm = []
    for _ in range(n_norm):
        vec = [
            float(rng.uniform(10.0, 50.0)),
            float(rng.uniform(50.0, 150.0)),
            float(rng.uniform(800.0, 3000.0)),
            float(rng.uniform(3000.0, 8000.0)),
            float(rng.uniform(3.0, 12.0)),
            float(rng.uniform(5.0, 30.0)),
            float(rng.uniform(2.0, 8.0)),
            float(rng.uniform(2.0, 8.0)),
            float(rng.uniform(0.80, 0.98)),
            float(rng.uniform(0.80, 0.98)),
            float(rng.uniform(0.80, 0.98)),
            float(rng.uniform(0.80, 0.98)),
            float(rng.uniform(0.80, 0.98)),
            float(rng.uniform(0.85, 0.98)),
            float(rng.uniform(0.02, 0.20)),
        ]
        X_norm.append(vec)

    X_atk = []
    for _ in range(n_atk):
        vec = [
            float(rng.uniform(5000.0, 25000.0)),
            float(rng.uniform(30000.0, 80000.0)),
            float(rng.uniform(300000.0, 1500000.0)),
            float(rng.uniform(1500000.0, 5000000.0)),
            float(rng.uniform(100.0, 800.0)),
            float(rng.uniform(0.5, 3.0)),
            float(rng.uniform(100.0, 500.0)),
            float(rng.uniform(1.0, 2.0)),
            float(rng.uniform(0.05, 0.25)),
            float(rng.uniform(0.01, 0.15)),
            float(rng.uniform(0.10, 0.30)),
            float(rng.uniform(0.10, 0.30)),
            float(rng.uniform(0.10, 0.30)),
            float(rng.uniform(0.05, 0.25)),
            float(rng.uniform(0.75, 0.95)),
        ]
        X_atk.append(vec)

    X = np.vstack([X_norm, X_atk])
    y = np.array([0] * n_norm + [1] * n_atk, dtype=int)
    return X, y


class AdaptiveModelUpdater:
    """
    Trains and evaluates candidate models against safety constraints.
    """

    def __init__(
        self,
        min_f1: float = 0.85,
        max_fpr: float = 0.05,
        max_latency_ms: float = 10.0,
    ) -> None:
        self.min_f1 = min_f1
        self.max_fpr = max_fpr
        self.max_latency_ms = max_latency_ms
        # Fixed benchmark validation dataset for comparing candidates
        self._val_X, self._val_y = _generate_synthetic_anchor_baseline(n_samples=120)

    def train_candidate(
        self,
        X_new: np.ndarray,
        y_new: np.ndarray,
        include_anchor: bool = True,
    ) -> Tuple[DecisionTreeClassifier, StandardScaler, float]:
        """
        Train a new candidate DecisionTree classifier.
        """
        if include_anchor:
            X_anc, y_anc = _generate_synthetic_anchor_baseline(n_samples=80)
            X_train = np.vstack([X_anc, X_new])
            y_train = np.concatenate([y_anc, y_new])
        else:
            X_train = X_new
            y_train = y_new

        start = time.perf_counter()
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_train)

        candidate = DecisionTreeClassifier(
            max_depth=5,
            class_weight="balanced",
            random_state=42,
        )
        candidate.fit(X_scaled, y_train)
        train_time = time.perf_counter() - start

        return candidate, scaler, train_time

    def evaluate_model(
        self,
        model: Any,
        scaler: StandardScaler,
        val_X: Optional[np.ndarray] = None,
        val_y: Optional[np.ndarray] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate model on held-out validation set and measure F1, FPR, accuracy, latency.
        """
        vX = val_X if val_X is not None else self._val_X
        vy = val_y if val_y is not None else self._val_y

        start = time.perf_counter()
        X_scaled = scaler.transform(vX)
        y_pred = model.predict(X_scaled)
        eval_time = (time.perf_counter() - start) * 1000.0  # ms
        latency_per_sample = eval_time / max(1, len(vX))

        acc = float(accuracy_score(vy, y_pred))
        f1 = float(f1_score(vy, y_pred, zero_division=0))
        prec = float(precision_score(vy, y_pred, zero_division=0))
        rec = float(recall_score(vy, y_pred, zero_division=0))

        # Confusion matrix: tn, fp, fn, tp
        tn, fp, fn, tp = confusion_matrix(vy, y_pred, labels=[0, 1]).ravel()
        fpr = float(fp / max(1, fp + tn))
        fnr = float(fn / max(1, fn + tp))

        return {
            "accuracy": round(acc, 4),
            "f1_score": round(f1, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "latency_ms": round(latency_per_sample, 4),
            "total_val_samples": len(vX),
        }

    def validate_candidate_safety(
        self,
        candidate_metrics: Dict[str, Any],
        current_metrics: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """
        Enforce quality gates and safety criteria.

        Must satisfy:
        1. F1 >= min_f1
        2. FPR <= max_fpr
        3. Latency <= max_latency_ms
        4. If current model metrics exist, candidate F1 must not degrade by > 0.03
        """
        f1 = candidate_metrics.get("f1_score", 0.0)
        fpr = candidate_metrics.get("false_positive_rate", 1.0)
        lat = candidate_metrics.get("latency_ms", 100.0)

        if f1 < self.min_f1:
            return False, f"Candidate F1 score ({f1:.4f}) below minimum safety threshold ({self.min_f1:.4f})"

        if fpr > self.max_fpr:
            return False, f"Candidate False Positive Rate ({fpr:.4f}) exceeds allowable limit ({self.max_fpr:.4f})"

        if lat > self.max_latency_ms:
            return False, f"Candidate inference latency ({lat:.2f}ms) exceeds max allowable ({self.max_latency_ms:.2f}ms)"

        if current_metrics:
            curr_f1 = current_metrics.get("f1_score", 0.0)
            if f1 < (curr_f1 - 0.03):
                return False, f"Candidate F1 ({f1:.4f}) regressed compared to active model ({curr_f1:.4f})"

        return True, "Passed all safety and performance criteria"

