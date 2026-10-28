"""
Online AutoML Service — orchestrator for controlled model retraining and deployment.

Controlled lifecycle:
  Recent validated data
  → drift/performance trigger
  → train candidates
  → evaluate F1/FPR/latency
  → reject failed candidates
  → select champion
  → version/register
  → deploy (via shared deployment gate)
  → monitor
  → rollback if validation fails
"""

from __future__ import annotations

import csv
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np

from shared_contracts.enums import CandidateStatus, ValidationStatus
from shared_contracts.timeutil import utc_now
from online_automl.candidates import AutoMLCandidate, build_candidate_suite, sanitize_vector
from online_automl.drift_trigger import AutoMLTriggerManager
from online_automl.evaluator import CandidateEvaluator, CandidateValidationPolicy
from online_automl.logger import AutoMLLogger
from online_automl.registry import AutoMLRegistry
from online_automl.selector import ChampionSelector

logger = logging.getLogger("intellishield.online_automl.service")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR = os.path.join(_BASE_DIR, "..", "logs")
FEATURES_CSV_PATH = os.path.join(_LOGS_DIR, "ml_features.csv")


@dataclass
class AutoMLDataset:
    """
    Dataset container tracking provenance, sample counts, feature schema, and synthetic flag.
    Supports 4-tuple unpacking (X_train, y_train, X_val, y_val) for seamless backwards compatibility.
    """
    X_train: List[List[float]]
    y_train: List[int]
    X_val: List[List[float]]
    y_val: List[int]
    is_synthetic: bool = False
    provenance: str = "real_network_csv"
    sample_counts: Dict[str, int] = field(default_factory=dict)
    feature_schema: str = "FEATURE_NAMES_15D"
    train_val_split: float = 0.7

    def __iter__(self):
        return iter((self.X_train, self.y_train, self.X_val, self.y_val))


def _generate_synthetic_benchmark_dataset() -> AutoMLDataset:
    """Generate realistic synthetic 15-D benchmark dataset for development/testing when no real CSV exists."""
    rng = np.random.RandomState(42)
    X_norm = []
    y_norm = []
    for _ in range(120):
        vec = [
            float(rng.uniform(10.0, 50.0)),    # packet_rate_mean
            float(rng.uniform(50.0, 150.0)),   # packet_rate_max
            float(rng.uniform(800.0, 3000.0)), # byte_rate_mean
            float(rng.uniform(3000.0, 8000.0)),# byte_rate_max
            float(rng.uniform(3.0, 12.0)),     # flow_count
            float(rng.uniform(5.0, 30.0)),     # duration_mean
            float(rng.uniform(2.0, 8.0)),      # unique_src_count
            float(rng.uniform(2.0, 8.0)),      # unique_dst_count
            float(rng.uniform(0.80, 0.98)),    # src_entropy
            float(rng.uniform(0.80, 0.98)),    # dst_entropy
            float(rng.uniform(0.80, 0.98)),    # packet_entropy
            float(rng.uniform(0.80, 0.98)),    # byte_entropy
            float(rng.uniform(0.80, 0.98)),    # flow_entropy
            float(rng.uniform(0.85, 0.98)),    # entropy_score
            float(rng.uniform(0.02, 0.20)),    # flow_concentration
        ]
        X_norm.append(vec)
        y_norm.append(0)

    X_atk = []
    y_atk = []
    for _ in range(80):
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
        y_atk.append(1)

    X_all = X_norm + X_atk
    y_all = y_norm + y_atk

    # Split 70/30 train/val
    idx = np.arange(len(X_all))
    rng.shuffle(idx)
    split = int(len(idx) * 0.7)

    train_idx, val_idx = idx[:split], idx[split:]
    X_train = [X_all[i] for i in train_idx]
    y_train = [y_all[i] for i in train_idx]
    X_val = [X_all[i] for i in val_idx]
    y_val = [y_all[i] for i in val_idx]

    return AutoMLDataset(
        X_train=X_train,
        y_train=y_train,
        X_val=X_val,
        y_val=y_val,
        is_synthetic=True,
        provenance="synthetic_benchmark_generator",
        sample_counts={
            "total": len(X_all),
            "train": len(X_train),
            "val": len(X_val),
            "normal": len(X_norm),
            "attack": len(X_atk),
        },
        feature_schema="FEATURE_NAMES_15D",
        train_val_split=0.7,
    )


def load_dataset_from_csv(csv_path: Optional[str] = None) -> AutoMLDataset:
    """
    Load dataset from ml_features.csv if available with >= 20 valid labelled samples.
    Otherwise, explicitly falls back to a synthetic benchmark dataset labeled as synthetic.
    """
    target_path = csv_path or FEATURES_CSV_PATH
    if not os.path.exists(target_path):
        logger.warning(
            "[OnlineAutoMLService] Real training data not found at '%s'. Falling back to SYNTHETIC benchmark dataset (labeled synthetic).",
            target_path,
        )
        return _generate_synthetic_benchmark_dataset()

    X, y = [], []
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                if len(row) >= 18:
                    try:
                        lbl_raw = row[2]
                        if lbl_raw == "" or lbl_raw is None:
                            continue
                        label = int(lbl_raw)
                        if label not in (0, 1):
                            continue
                        vec = [float(v) for v in row[3:18]]
                        if len(vec) == 15:
                            X.append(vec)
                            y.append(label)
                    except (ValueError, IndexError):
                        continue
    except Exception as exc:
        logger.warning("[load_dataset_from_csv] Could not read CSV: %s", exc)

    if len(X) < 20 or len(set(y)) < 2:
        logger.warning(
            "[OnlineAutoMLService] Insufficient real data in '%s' (%d rows, %d classes) — falling back to SYNTHETIC benchmark dataset (labeled synthetic).",
            target_path,
            len(X),
            len(set(y)),
        )
        return _generate_synthetic_benchmark_dataset()

    idx = np.arange(len(X))
    np.random.RandomState(42).shuffle(idx)
    split = int(len(idx) * 0.7)

    X_train = [X[i] for i in idx[:split]]
    y_train = [y[i] for i in idx[:split]]
    X_val = [X[i] for i in idx[split:]]
    y_val = [y[i] for i in idx[split:]]

    logger.info(
        "[OnlineAutoMLService] Loaded REAL network dataset (%d total rows, %d train, %d val) from %s",
        len(X),
        len(X_train),
        len(X_val),
        target_path,
    )

    return AutoMLDataset(
        X_train=X_train,
        y_train=y_train,
        X_val=X_val,
        y_val=y_val,
        is_synthetic=False,
        provenance=f"real_csv:{target_path}",
        sample_counts={
            "total": len(X),
            "train": len(X_train),
            "val": len(X_val),
            "normal": sum(1 for val in y if val == 0),
            "attack": sum(1 for val in y if val == 1),
        },
        feature_schema="FEATURE_NAMES_15D",
        train_val_split=0.7,
    )


class OnlineAutoMLService:
    """
    Singleton service orchestrating Online AutoML lifecycle.
    """

    def __init__(self, allow_synthetic_promotion: bool = False) -> None:
        self.trigger_mgr = AutoMLTriggerManager(min_interval_sec=300.0)
        self.evaluator = CandidateEvaluator()
        self.selector = ChampionSelector()
        self.registry = AutoMLRegistry()
        self.automl_logger = AutoMLLogger()
        self.last_run_report: Optional[Dict[str, Any]] = None
        self.recent_candidates: List[AutoMLCandidate] = []
        self.is_running: bool = False
        self.allow_synthetic_promotion = allow_synthetic_promotion

        # Deployment promotion callbacks: cb(estimator, scaler, metrics, is_synthetic, provenance)
        self._on_champion_promoted_callbacks: List[Callable[[Any, Any, Dict[str, Any], bool, str], None]] = []

    def register_on_champion_promoted(
        self, callback: Callable[[Any, Any, Dict[str, Any], bool, str], None]
    ) -> None:
        """Register callback invoked when a new champion model is promoted."""
        self._on_champion_promoted_callbacks.append(callback)

    def run_automl_pipeline(
        self,
        force: bool = False,
        adwin_drift: bool = False,
        perf_degraded: bool = False,
        X_train: Optional[List[List[float]]] = None,
        y_train: Optional[List[int]] = None,
        X_val: Optional[List[List[float]]] = None,
        y_val: Optional[List[int]] = None,
        dataset_csv_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute full controlled AutoML pipeline:
          Check trigger -> Train candidates -> Evaluate metrics -> Filter gates
          -> Select champion -> Register & deploy -> Monitor/health check
        """
        should_run, reason = self.trigger_mgr.should_trigger(
            force=force, adwin_drift=adwin_drift, perf_degraded=perf_degraded
        )

        if not should_run:
            return {
                "ran": False,
                "reason": reason,
                "champion": self.registry.current_champion.algorithm_name if self.registry.current_champion else "None",
            }

        self.is_running = True
        self.automl_logger.log_event("AUTOML_RUN_STARTED", f"Starting AutoML run (trigger: {reason})")

        try:
            # 1. Load dataset if not passed explicitly
            if X_train is None or y_train is None or X_val is None or y_val is None:
                dataset = load_dataset_from_csv(dataset_csv_path)
                X_tr, y_tr, X_v, y_v = dataset.X_train, dataset.y_train, dataset.X_val, dataset.y_val
                is_synthetic = dataset.is_synthetic
                provenance = dataset.provenance
                sample_counts = dataset.sample_counts
            else:
                X_tr, y_tr, X_v, y_v = X_train, y_train, X_val, y_val
                is_synthetic = False
                provenance = "caller_provided_data"
                sample_counts = {"train": len(X_tr), "val": len(X_v), "total": len(X_tr) + len(X_v)}

            # 2. Build candidate suite
            candidates = build_candidate_suite()
            evaluated_candidates: List[AutoMLCandidate] = []
            eval_reports: List[Dict[str, Any]] = []

            # 3. Train & evaluate candidates
            for cand in candidates:
                try:
                    cand.fit(X_tr, y_tr)
                    metrics, val_res = self.evaluator.evaluate_candidate(cand, X_v, y_v)
                    # Explicitly tag data provenance to avoid metric spoofing
                    metrics["is_synthetic"] = is_synthetic
                    metrics["data_provenance"] = provenance
                    cand.metrics.update(metrics)

                    self.automl_logger.log_validation_summary(val_res)
                    evaluated_candidates.append(cand)
                    eval_reports.append({
                        "candidate_id": cand.candidate_id,
                        "algorithm": cand.algorithm_name,
                        "model_type": cand.model_type,
                        "status": cand.status.value,
                        "f1_score": metrics.get("f1_score"),
                        "false_positive_rate": metrics.get("false_positive_rate"),
                        "latency_ms": metrics.get("latency_ms"),
                        "accuracy": metrics.get("accuracy"),
                        "is_synthetic": is_synthetic,
                        "data_provenance": provenance,
                        "reason": val_res.reason,
                    })
                except Exception as exc:
                    cand.status = CandidateStatus.REJECTED
                    logger.error("[OnlineAutoMLService] Failed training/evaluating candidate %s: %s", cand.algorithm_name, exc)

            self.recent_candidates = evaluated_candidates

            # 4. Select Champion
            new_champion, select_reason = self.selector.select_champion(
                evaluated_candidates, current_champion=self.registry.current_champion
            )

            deployment_status = "NO_CHANGE"
            promoted_name = "None"

            if new_champion is not None:
                # 5. Register champion
                val_res = self.evaluator.evaluate_candidate(new_champion, X_v, y_v)[1]
                self.registry.register_champion(new_champion, val_res)
                promoted_name = new_champion.algorithm_name

                # Check synthetic deployment safety gate
                if is_synthetic and not self.allow_synthetic_promotion:
                    deployment_status = (
                        "BLOCKED_SYNTHETIC_DATA (Trained on synthetic benchmark; "
                        "promotion to live SDN controller blocked without allow_synthetic_promotion=True)"
                    )
                    self.automl_logger.log_event(
                        "CHAMPION_PROMOTION_BLOCKED",
                        f"Champion {promoted_name} promotion blocked due to synthetic dataset.",
                        {"reason": select_reason, "provenance": provenance},
                    )
                else:
                    deployment_status = "DEPLOYED"
                    self.automl_logger.log_event("CHAMPION_PROMOTED", f"Promoted {promoted_name}", {"reason": select_reason})

                    # Notify registered deployment callbacks (e.g. ModelDeploymentGate)
                    for cb in self._on_champion_promoted_callbacks:
                        try:
                            cb(new_champion.estimator, new_champion.scaler, new_champion.metrics, is_synthetic, provenance)
                        except Exception as exc:
                            logger.error("[OnlineAutoMLService] Deployment notification failed: %s", exc)

                    # 6. Post-deploy sanity check (Health monitoring)
                    if float(new_champion.metrics.get("f1_score", 0.0)) < 0.50:
                        logger.warning("[OnlineAutoMLService] Post-deploy health check failed — initiating rollback!")
                        restored, roll_reason = self.rollback()
                        deployment_status = f"ROLLED_BACK ({roll_reason})"

            report = {
                "ran": True,
                "trigger_reason": reason,
                "timestamp": datetime.now().isoformat(),
                "dataset_size": {"train": len(X_tr), "val": len(X_v)},
                "dataset_provenance": provenance,
                "is_synthetic": is_synthetic,
                "sample_counts": sample_counts,
                "candidates_evaluated": len(evaluated_candidates),
                "champion_selected": promoted_name,
                "selection_reason": select_reason,
                "deployment_status": deployment_status,
                "candidates": eval_reports,
            }
            self.last_run_report = report
            self.automl_logger.log_event("AUTOML_RUN_FINISHED", f"Finished run (champion: {promoted_name})", report)
            return report

        finally:
            self.is_running = False

    def rollback(self) -> Tuple[Optional[AutoMLCandidate], str]:
        """
        Trigger automated or manual rollback to previous champion model.
        """
        restored, reason = self.registry.rollback()
        self.automl_logger.log_event("MODEL_ROLLBACK", reason)
        return restored, reason

    def get_status(self) -> Dict[str, Any]:
        """
        Return current AutoML status JSON for UI dashboard cards.
        """
        champ = self.registry.current_champion
        champ_dict = None
        if champ is not None:
            champ_dict = {
                "algorithm": champ.algorithm_name,
                "model_id": champ.model_id,
                "candidate_id": champ.candidate_id,
                "status": champ.status.value,
                "metrics": champ.metrics,
                "created_at": champ.created_at.isoformat(),
                "is_synthetic": champ.metrics.get("is_synthetic", False),
                "data_provenance": champ.metrics.get("data_provenance", "unknown"),
            }

        candidates_summary = []
        for c in self.recent_candidates:
            candidates_summary.append({
                "algorithm": c.algorithm_name,
                "candidate_id": c.candidate_id,
                "status": c.status.value,
                "metrics": c.metrics,
            })

        return {
            "is_running": self.is_running,
            "champion": champ_dict,
            "previous_champion": self.registry.previous_champion.algorithm_name if self.registry.previous_champion else None,
            "candidates": candidates_summary,
            "last_trigger_reason": self.trigger_mgr.last_trigger_reason,
            "total_triggers": self.trigger_mgr.total_triggers,
            "min_interval_sec": self.trigger_mgr.min_interval_sec,
            "last_rollback_reason": self.registry.last_rollback_reason,
            "last_run_report": self.last_run_report,
            "version_history": self.registry.version_history[-5:],
            "allow_synthetic_promotion": self.allow_synthetic_promotion,
        }


# Singleton service instance
automl_service = OnlineAutoMLService()
