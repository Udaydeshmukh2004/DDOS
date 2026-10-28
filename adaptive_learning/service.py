"""
Adaptive Learning Service orchestrator for IntelliShield SDN.

Coordinates drift monitoring, verified sample collection, candidate retraining,
safety evaluation, model promotion, hot-swapping, and rollback.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import numpy as np

from shared_contracts.timeutil import utc_now
from adaptive_learning.drift_monitor import DriftMonitor
from adaptive_learning.model_registry import AdaptiveModelRegistry, RegisteredModel
from adaptive_learning.model_updater import AdaptiveModelUpdater
from adaptive_learning.sample_buffer import VerifiedSampleBuffer

logger = logging.getLogger("intellishield.adaptive_learning.service")


class AdaptiveLearningService:
    """
    Singleton orchestrator for Adaptive Learning for Evolving Attacks.
    """

    def __init__(
        self,
        min_adaptation_interval_sec: float = 120.0,
        min_normal_samples: int = 25,
        min_attack_samples: int = 10,
    ) -> None:
        self.min_interval_sec = min_adaptation_interval_sec
        self.min_normal_samples = min_normal_samples
        self.min_attack_samples = min_attack_samples

        self.drift_monitor = DriftMonitor()
        self.sample_buffer = VerifiedSampleBuffer()
        self.updater = AdaptiveModelUpdater()
        self.registry = AdaptiveModelRegistry()

        self._last_adaptation_at: Optional[datetime] = None
        self._lock = threading.Lock()
        self._on_model_promoted_callbacks: List[Callable[[Any, Any], None]] = []

        # Bootstrap initial baseline model if none is active
        self._bootstrap_initial_model()

    def _bootstrap_initial_model(self) -> None:
        """Create baseline model so an active model is always ready."""
        try:
            cand_tree, scaler, _ = self.updater.train_candidate(
                np.empty((0, 15)), np.empty((0,), dtype=int), include_anchor=True
            )
            metrics = self.updater.evaluate_model(cand_tree, scaler)
            cand = self.registry.register_candidate(cand_tree, scaler, metrics, algorithm="Initial_Baseline_Tree")
            self.registry.promote_candidate(cand, reason="Bootstrap initial baseline model")
        except Exception as exc:
            logger.error("[AdaptiveLearningService] Could not bootstrap initial model: %s", exc)

    def register_on_model_promoted(self, callback: Callable[[Any, Any], None]) -> None:
        """Register callback invoked with (estimator, scaler) when a new model is promoted."""
        self._on_model_promoted_callbacks.append(callback)

    def process_monitoring_cycle(
        self,
        switch_id: int,
        feature_vector: Sequence[float],
        prediction_status: Optional[str] = None,
        adwin_alerts: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Record cycle telemetry into drift monitor and trigger adaptation if drift occurs.
        """
        self.drift_monitor.record_cycle_features(switch_id, feature_vector, prediction_status)

        drift_event = None
        if adwin_alerts:
            drift_event = self.drift_monitor.record_adwin_drift(switch_id, adwin_alerts)

        # If ADWIN flagged drift, attempt candidate adaptation
        if drift_event is not None:
            return self.trigger_adaptation(reason=f"ADWIN drift detected: {drift_event.affected_features}")

        return None

    def add_verified_sample(
        self,
        vector: Sequence[float],
        label: int,
        source: str,
        verified: bool = False,
        confidence: float = 1.0,
    ) -> bool:
        """
        Safely collect a verified sample (from R7 verification, ground truth, or simulation).
        """
        return self.sample_buffer.add_sample(
            vector=vector,
            label=label,
            source=source,
            verified=verified,
            confidence=confidence,
        )

    def trigger_adaptation(self, force: bool = False, reason: str = "manual_trigger") -> Dict[str, Any]:
        """
        Execute candidate training and evaluation pipeline.
        """
        now = utc_now()
        if not force and self._last_adaptation_at is not None:
            elapsed = (now - self._last_adaptation_at).total_seconds()
            if elapsed < self.min_interval_sec:
                return {
                    "adapted": False,
                    "reason": f"Cooldown active: {elapsed:.1f}s elapsed (minimum {self.min_interval_sec:.1f}s)",
                }

        with self._lock:
            # Check sample sufficiency
            dataset = self.sample_buffer.get_training_dataset(
                min_normal=self.min_normal_samples,
                min_attack=self.min_attack_samples,
            )

            if dataset is None and not force:
                stats = self.sample_buffer.get_stats()
                return {
                    "adapted": False,
                    "reason": (
                        f"Insufficient verified samples: {stats['normal_samples_count']}/"
                        f"{self.min_normal_samples} normal, {stats['attack_samples_count']}/"
                        f"{self.min_attack_samples} attack"
                    ),
                }

            if dataset is not None:
                X_new, y_new = dataset
            else:
                # Force mode with baseline anchor
                X_new, y_new = np.empty((0, 15)), np.empty((0,), dtype=int)

            logger.info("[AdaptiveLearningService] Starting candidate model adaptation (trigger: %s)...", reason)
            try:
                candidate_tree, scaler, train_time = self.updater.train_candidate(
                    X_new, y_new, include_anchor=True
                )
                metrics = self.updater.evaluate_model(candidate_tree, scaler)
                metrics["fit_time_sec"] = round(train_time, 4)

                cand = self.registry.register_candidate(
                    estimator=candidate_tree,
                    scaler=scaler,
                    metrics=metrics,
                    algorithm="Adaptive_DecisionTree",
                )

                # Validate against safety constraints and active model
                current_metrics = self.registry.active_model.metrics if self.registry.active_model else None
                passed, safety_reason = self.updater.validate_candidate_safety(
                    candidate_metrics=metrics,
                    current_metrics=current_metrics,
                )

                if not passed:
                    self.registry.reject_candidate(cand, reason=safety_reason)
                    self._last_adaptation_at = now
                    return {
                        "adapted": False,
                        "status": "REJECTED",
                        "reason": safety_reason,
                        "candidate_metrics": metrics,
                    }

                # Passed safety gates -> Promote
                promoted = self.registry.promote_candidate(cand, reason=f"{reason} — {safety_reason}")
                self._last_adaptation_at = now

                # Notify hot-swap subscribers
                for cb in self._on_model_promoted_callbacks:
                    try:
                        cb(promoted.estimator, promoted.scaler)
                    except Exception as exc:
                        logger.error("[AdaptiveLearningService] Callback notification failed: %s", exc)

                return {
                    "adapted": True,
                    "status": "PROMOTED",
                    "promoted_version": promoted.version_tag,
                    "metrics": metrics,
                    "reason": promoted.promotion_reason,
                }

            except Exception as exc:
                logger.error("[AdaptiveLearningService] Adaptation failed: %s", exc, exc_info=True)
                return {"adapted": False, "status": "ERROR", "error": str(exc)}

    def rollback(self) -> Tuple[bool, str]:
        """Rollback to the previous known-good model."""
        restored, msg = self.registry.rollback()
        if restored is not None:
            for cb in self._on_model_promoted_callbacks:
                try:
                    cb(restored.estimator, restored.scaler)
                except Exception as exc:
                    logger.error("[AdaptiveLearningService] Rollback callback error: %s", exc)
            return True, msg
        return False, msg

    def get_status(self) -> Dict[str, Any]:
        """Comprehensive status for API and UI."""
        return {
            "drift": self.drift_monitor.get_drift_status(),
            "samples": self.sample_buffer.get_stats(),
            "registry": self.registry.get_status(),
            "last_adaptation_timestamp": self._last_adaptation_at.isoformat() if self._last_adaptation_at else None,
            "min_interval_sec": self.min_interval_sec,
        }


# Singleton instance
adaptive_service = AdaptiveLearningService()

