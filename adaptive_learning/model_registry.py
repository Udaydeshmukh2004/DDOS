"""
Model Registry and Version Management for Adaptive Learning.

Manages model versioning, artifacts persistence, promotion audits,
and rollback to previous known-good models.
"""

from __future__ import annotations

import json
import logging
import os
import pickle
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from shared_contracts.enums import ModelStatus
from shared_contracts.models import ModelVersion
from shared_contracts.timeutil import ensure_utc, utc_now

logger = logging.getLogger("intellishield.adaptive_learning.model_registry")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR = os.path.join(_BASE_DIR, "..", "logs")
_REGISTRY_DIR = os.path.join(_LOGS_DIR, "models", "adaptive")
_AUDIT_LOG_PATH = os.path.join(_LOGS_DIR, "adaptive_model_audit.jsonl")


@dataclass
class RegisteredModel:
    model_id: str
    version_tag: str
    algorithm: str
    estimator: Any
    scaler: Any
    metrics: Dict[str, Any]
    created_at: datetime
    status: str  # "ACTIVE", "CANDIDATE", "REJECTED", "ROLLED_BACK", "ARCHIVED"
    promotion_reason: str = ""
    rejection_reason: str = ""


class AdaptiveModelRegistry:
    """
    Registry maintaining active and historical models for adaptive learning.
    """

    def __init__(self, registry_dir: Optional[str] = None) -> None:
        self.registry_dir = registry_dir or _REGISTRY_DIR
        os.makedirs(self.registry_dir, exist_ok=True)
        self.active_model: Optional[RegisteredModel] = None
        self.previous_model: Optional[RegisteredModel] = None
        self.version_history: List[Dict[str, Any]] = []
        self._version_counter: int = 1

    def register_candidate(
        self,
        estimator: Any,
        scaler: Any,
        metrics: Dict[str, Any],
        algorithm: str = "Adaptive_DecisionTree",
    ) -> RegisteredModel:
        """Register a freshly evaluated candidate."""
        model_id = f"adapt_{uuid.uuid4().hex[:8]}"
        version_tag = f"v{self._version_counter}.0-candidate"

        reg = RegisteredModel(
            model_id=model_id,
            version_tag=version_tag,
            algorithm=algorithm,
            estimator=estimator,
            scaler=scaler,
            metrics=metrics,
            created_at=utc_now(),
            status="CANDIDATE",
        )
        return reg

    def promote_candidate(
        self,
        candidate: RegisteredModel,
        reason: str,
    ) -> RegisteredModel:
        """Promote a candidate model to ACTIVE."""
        if candidate is None:
            raise ValueError("Cannot promote null candidate model")
        if not isinstance(candidate, RegisteredModel):
            raise ValueError(f"Invalid candidate type: {type(candidate)}")
        if candidate.status == "REJECTED":
            raise ValueError(
                f"Cannot promote a REJECTED candidate model ({candidate.version_tag})"
            )

        # Archive current active model as previous model
        if self.active_model is not None:
            self.active_model.status = "ARCHIVED"
            self.previous_model = self.active_model

        candidate.status = "ACTIVE"
        candidate.promotion_reason = reason
        candidate.version_tag = f"v{self._version_counter}.0-active"
        self._version_counter += 1

        self.active_model = candidate

        # Persist model artifact
        self._save_model_artifact(candidate)

        # Audit log
        self._log_audit("PROMOTION", candidate, reason)
        logger.info(
            "[AdaptiveModelRegistry] Promoted candidate %s to active (%s)",
            candidate.version_tag,
            reason,
        )
        return candidate

    def reject_candidate(
        self,
        candidate: RegisteredModel,
        reason: str,
    ) -> None:
        """Record candidate rejection."""
        candidate.status = "REJECTED"
        candidate.rejection_reason = reason
        self._log_audit("REJECTION", candidate, reason)
        logger.warning(
            "[AdaptiveModelRegistry] Rejected candidate %s: %s",
            candidate.version_tag,
            reason,
        )

    def rollback(self) -> Tuple[Optional[RegisteredModel], str]:
        """
        Roll back active model to the previous known-good model.
        """
        if self.previous_model is None:
            return None, "No previous model version available for rollback."

        curr = self.active_model
        if curr is not None:
            curr.status = "ROLLED_BACK"
            self._log_audit("ROLLBACK_SRC", curr, "Rolled back due to operator request or health fault")

        restored = self.previous_model
        restored.status = "ACTIVE"
        restored.promotion_reason = f"Restored via rollback from {curr.version_tag if curr else 'unknown'}"
        self.active_model = restored
        self.previous_model = None

        self._save_model_artifact(restored)
        self._log_audit("ROLLBACK_RESTORED", restored, restored.promotion_reason)
        logger.info("[AdaptiveModelRegistry] Successfully rolled back to %s", restored.version_tag)
        return restored, f"Restored previous model {restored.version_tag}"

    def _save_model_artifact(self, model: RegisteredModel) -> str:
        """Serialize model estimator and scaler to disk."""
        path = os.path.join(self.registry_dir, f"{model.model_id}.pkl")
        try:
            with open(path, "wb") as f:
                pickle.dump(
                    {
                        "model_id": model.model_id,
                        "version": model.version_tag,
                        "algorithm": model.algorithm,
                        "estimator": model.estimator,
                        "scaler": model.scaler,
                        "metrics": model.metrics,
                        "created_at": model.created_at.isoformat(),
                    },
                    f,
                )
            # Also save as latest_active.pkl
            latest_path = os.path.join(self.registry_dir, "latest_active.pkl")
            with open(latest_path, "wb") as f:
                pickle.dump(
                    {
                        "model_id": model.model_id,
                        "version": model.version_tag,
                        "algorithm": model.algorithm,
                        "estimator": model.estimator,
                        "scaler": model.scaler,
                        "metrics": model.metrics,
                    },
                    f,
                )
            return path
        except Exception as exc:
            logger.error("[AdaptiveModelRegistry] Failed to save artifact: %s", exc)
            return ""

    def _log_audit(self, action: str, model: RegisteredModel, reason: str) -> None:
        """Append promotion or rejection entry to audit log."""
        record = {
            "timestamp": utc_now().isoformat(),
            "action": action,
            "model_id": model.model_id,
            "version": model.version_tag,
            "algorithm": model.algorithm,
            "metrics": model.metrics,
            "reason": reason,
        }
        self.version_history.append(record)
        try:
            with open(_AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as exc:
            logger.error("[AdaptiveModelRegistry] Failed to write audit log: %s", exc)

    def get_status(self) -> Dict[str, Any]:
        """Status overview for UI and APIs."""
        return {
            "active_model": {
                "model_id": self.active_model.model_id,
                "version": self.active_model.version_tag,
                "algorithm": self.active_model.algorithm,
                "metrics": self.active_model.metrics,
                "created_at": self.active_model.created_at.isoformat(),
                "promotion_reason": self.active_model.promotion_reason,
            }
            if self.active_model
            else None,
            "has_previous_model": self.previous_model is not None,
            "previous_model_version": self.previous_model.version_tag if self.previous_model else None,
            "total_audit_events": len(self.version_history),
            "recent_audit_history": self.version_history[-5:],
        }

