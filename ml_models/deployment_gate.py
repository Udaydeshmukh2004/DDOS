"""
================================================================================
IntelliShield SDN — Shared Model Deployment Gate
================================================================================

File        : ml_models/deployment_gate.py
Description :
    Unified, thread-safe deployment gate coordinating model promotion between:
      1. Novelty R9: Adaptive Learning (ADWIN concept-drift triggered)
      2. Novelty R1: Online AutoML (Champion selector)

    Prevents race conditions, overwrites, incompatible model assignments,
    regression, and unauthorized promotion of synthetic-trained benchmark models
    to the live SDN controller.
================================================================================
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np

from shared_contracts.timeutil import utc_now
from ml_models.feature_builder import FEATURE_NAMES

logger = logging.getLogger("intellishield.deployment_gate")

N_FEATURES = len(FEATURE_NAMES)  # 15


class CompatibleModelAdapter:
    """
    Adapter ensuring any candidate estimator provides the exact interface
    expected by AnomalyDetector._dt:
      - predict(X_scaled) -> array of 0 (NORMAL) or 1 (ATTACK)
      - predict_proba(X_scaled) -> array of shape (n, 2)
      - feature_importances_ -> array of length 15
    """

    def __init__(self, estimator: Any, algorithm_name: str = "Unknown"):
        self.estimator = estimator
        self.algorithm_name = algorithm_name

    def predict(self, X_scaled: np.ndarray) -> np.ndarray:
        raw = self.estimator.predict(X_scaled)
        # Handle unsupervised outputs (-1: anomaly, 1: normal)
        if hasattr(self.estimator, "offset_") or "IsolationForest" in type(self.estimator).__name__:
            return np.where(raw == -1, 1, 0)
        return np.array(raw, dtype=int)

    def predict_proba(self, X_scaled: np.ndarray) -> np.ndarray:
        if hasattr(self.estimator, "predict_proba"):
            probs = self.estimator.predict_proba(X_scaled)
            if probs.ndim == 2 and probs.shape[1] == 2:
                return probs
            elif probs.ndim == 2 and probs.shape[1] == 1:
                p1 = probs[:, 0]
                return np.column_stack([1.0 - p1, p1])
        elif hasattr(self.estimator, "decision_function"):
            scores = self.estimator.decision_function(X_scaled)
            # Invert: lower decision score -> higher anomaly probability
            s_min, s_max = np.min(scores), np.max(scores)
            denom = s_max - s_min if s_max != s_min else 1.0
            norm = (scores - s_min) / (denom + 1e-6)
            p_attack = np.clip(1.0 - norm, 0.0, 1.0)
            return np.column_stack([1.0 - p_attack, p_attack])

        # Fallback to binary hard predictions as probabilities
        preds = self.predict(X_scaled)
        p1 = preds.astype(float)
        return np.column_stack([1.0 - p1, p1])

    @property
    def feature_importances_(self) -> np.ndarray:
        if hasattr(self.estimator, "feature_importances_"):
            return self.estimator.feature_importances_
        # Uniform fallback for algorithms without tree importances
        return np.full((N_FEATURES,), 1.0 / N_FEATURES)


class ModelDeploymentGate:
    """
    Shared Gate controlling all live model deployments to the SDN controller.
    """

    def __init__(
        self,
        allow_synthetic_promotion: bool = False,
        min_f1_threshold: float = 0.60,
    ) -> None:
        self.allow_synthetic_promotion = allow_synthetic_promotion
        self.min_f1_threshold = min_f1_threshold
        self._lock = threading.Lock()

        # Active state
        self.active_source: Optional[str] = "bootstrap"
        self.active_version: Optional[str] = "baseline_v1"
        self.active_estimator: Optional[Any] = None
        self.active_scaler: Optional[Any] = None
        self.active_metrics: Dict[str, Any] = {}
        self.active_updated_at: Optional[datetime] = None

        # Rollback stack (previous known-good)
        self._previous_state: Optional[Dict[str, Any]] = None

        # Listeners / callbacks for actual detector update
        self._on_deploy_callbacks: List[Callable[[Any, Any, str, str], None]] = []
        self._audit_history: List[Dict[str, Any]] = []

    def register_on_deploy(self, callback: Callable[[Any, Any, str, str], None]) -> None:
        """Register callback invoked with (estimator, scaler, source, version)."""
        self._on_deploy_callbacks.append(callback)

    def validate_compatibility(self, estimator: Any, scaler: Any) -> Tuple[bool, Optional[Any], str]:
        """
        Validate that the estimator and scaler operate on 15-D feature vectors
        and satisfy the supervised prediction interface.
        """
        if scaler is None or estimator is None:
            return False, None, "Scaler and estimator must not be None"

        try:
            # Test transform on 15-D vector
            dummy_15d = np.zeros((1, N_FEATURES), dtype=float)
            scaled = scaler.transform(dummy_15d)
            if scaled.shape[1] != N_FEATURES:
                return False, None, f"Scaler output dimension {scaled.shape[1]} != {N_FEATURES}"

            # Test prediction
            adapted = CompatibleModelAdapter(estimator, type(estimator).__name__)
            pred = adapted.predict(scaled)
            if len(pred) != 1 or pred[0] not in (0, 1):
                return False, None, f"Estimator produced invalid binary prediction: {pred}"

            probs = adapted.predict_proba(scaled)
            if probs.shape != (1, 2):
                return False, None, f"Estimator predict_proba produced invalid shape: {probs.shape}"

            return True, adapted, "Compatible"
        except Exception as exc:
            return False, None, f"Compatibility validation exception: {exc}"

    def request_deployment(
        self,
        source: str,
        version: str,
        estimator: Any,
        scaler: Any,
        metrics: Optional[Dict[str, Any]] = None,
        is_synthetic: bool = False,
        provenance: str = "unknown",
        force: bool = False,
    ) -> Tuple[bool, str]:
        """
        Evaluate and atomically apply model promotion to the live detector.
        """
        metrics = metrics or {}
        now = utc_now()

        with self._lock:
            # 1. Synthetic data guard
            if is_synthetic and not self.allow_synthetic_promotion:
                reason = (
                    f"Deployment rejected: Candidate '{version}' from '{source}' was trained on "
                    f"SYNTHETIC data ({provenance}). Promotion to live controller blocked."
                )
                logger.warning("[ModelDeploymentGate] %s", reason)
                self._record_audit(source, version, False, reason, metrics)
                return False, reason

            # 2. Interface compatibility check
            compatible, adapted_estimator, comp_reason = self.validate_compatibility(estimator, scaler)
            if not compatible:
                reason = f"Deployment rejected: Incompatible estimator interface ({comp_reason})"
                logger.error("[ModelDeploymentGate] %s", reason)
                self._record_audit(source, version, False, reason, metrics)
                return False, reason

            # 3. Quality / Regression check
            cand_f1 = float(metrics.get("f1_score", 0.0) or 0.0)
            if not force and cand_f1 < self.min_f1_threshold:
                reason = (
                    f"Deployment rejected: Candidate F1 ({cand_f1:.4f}) is below minimum "
                    f"threshold ({self.min_f1_threshold:.4f})"
                )
                logger.warning("[ModelDeploymentGate] %s", reason)
                self._record_audit(source, version, False, reason, metrics)
                return False, reason

            # Active model comparison
            if not force and self.active_metrics:
                active_f1 = float(self.active_metrics.get("f1_score", 0.0) or 0.0)
                # Reject if severe regression (> 10% drop)
                if active_f1 > 0.5 and cand_f1 < (active_f1 - 0.10):
                    reason = (
                        f"Deployment rejected: Severe regression detected. Candidate F1 {cand_f1:.4f} "
                        f"is lower than active model F1 {active_f1:.4f}"
                    )
                    logger.warning("[ModelDeploymentGate] %s", reason)
                    self._record_audit(source, version, False, reason, metrics)
                    return False, reason

            # 4. Save current state for rollback
            if self.active_estimator is not None and self.active_scaler is not None:
                self._previous_state = {
                    "source": self.active_source,
                    "version": self.active_version,
                    "estimator": self.active_estimator,
                    "scaler": self.active_scaler,
                    "metrics": dict(self.active_metrics),
                    "updated_at": self.active_updated_at,
                }

            # 5. Apply promotion
            self.active_source = source
            self.active_version = version
            self.active_estimator = adapted_estimator
            self.active_scaler = scaler
            self.active_metrics = dict(metrics)
            self.active_updated_at = now

            for cb in self._on_deploy_callbacks:
                try:
                    cb(adapted_estimator, scaler, source, version)
                except Exception as exc:
                    logger.error("[ModelDeploymentGate] Deployment callback failed: %s", exc)

            reason = f"Promoted {version} from {source} (F1: {cand_f1:.4f}, prov: {provenance})"
            logger.info("[ModelDeploymentGate] %s", reason)
            self._record_audit(source, version, True, reason, metrics)
            return True, reason

    def rollback(self) -> Tuple[bool, str]:
        """Rollback to the previous known-good model atomically."""
        with self._lock:
            if not self._previous_state:
                return False, "No previous model available for rollback"

            prev = self._previous_state
            self.active_source = prev["source"]
            self.active_version = prev["version"]
            self.active_estimator = prev["estimator"]
            self.active_scaler = prev["scaler"]
            self.active_metrics = prev["metrics"]
            self.active_updated_at = utc_now()
            self._previous_state = None  # Consume rollback state

            for cb in self._on_deploy_callbacks:
                try:
                    cb(self.active_estimator, self.active_scaler, self.active_source, self.active_version)
                except Exception as exc:
                    logger.error("[ModelDeploymentGate] Rollback callback error: %s", exc)

            reason = f"Rolled back to {self.active_version} from {self.active_source}"
            logger.info("[ModelDeploymentGate] %s", reason)
            return True, reason

    def get_status(self) -> Dict[str, Any]:
        """Return status dictionary for UI and API."""
        return {
            "active_source": self.active_source,
            "active_version": self.active_version,
            "active_metrics": self.active_metrics,
            "active_updated_at": self.active_updated_at.isoformat() if self.active_updated_at else None,
            "has_rollback_model": self._previous_state is not None,
            "allow_synthetic_promotion": self.allow_synthetic_promotion,
            "audit_history": self._audit_history[-10:],
        }

    def _record_audit(self, source: str, version: str, success: bool, reason: str, metrics: Dict[str, Any]) -> None:
        self._audit_history.append({
            "timestamp": utc_now().isoformat(),
            "source": source,
            "version": version,
            "success": success,
            "reason": reason,
            "metrics": metrics,
        })


# Shared singleton gate
shared_deployment_gate = ModelDeploymentGate()

