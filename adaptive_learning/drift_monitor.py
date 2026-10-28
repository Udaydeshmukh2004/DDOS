"""
Drift Monitor for Adaptive Learning in IntelliShield SDN.

Monitors rolling feature distributions (mean, std), prediction behavior,
and integrates with the existing ADWIN drift detector alerts.
Records drift events with timestamps, affected features, and drift status.
"""

from __future__ import annotations

import json
import logging
import math
import os
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Sequence

from shared_contracts.timeutil import ensure_utc, utc_now
from ml_models.feature_builder import FEATURE_NAMES

logger = logging.getLogger("intellishield.adaptive_learning.drift_monitor")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR = os.path.join(_BASE_DIR, "..", "logs")
DRIFT_EVENTS_PATH = os.path.join(_LOGS_DIR, "drift_events.jsonl")


@dataclass
class DriftEvent:
    event_id: str
    timestamp: str
    switch_id: int
    affected_features: List[str]
    drift_status: str
    magnitude: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DriftMonitor:
    """
    Monitors feature distributions and drift alerts over time.
    """

    def __init__(self, window_size: int = 100, log_path: Optional[str] = None) -> None:
        self.window_size = window_size
        self.log_path = log_path or DRIFT_EVENTS_PATH
        self._history: Deque[List[float]] = deque(maxlen=window_size)
        self._status_counts: Dict[str, int] = {"NORMAL": 0, "SUSPICIOUS": 0, "ATTACK": 0, "UNKNOWN": 0}
        self._drift_events: List[DriftEvent] = []
        self._last_drift_detected_at: Optional[datetime] = None
        self._consecutive_drift_count: int = 0

    def record_cycle_features(
        self,
        switch_id: int,
        feature_vector: Sequence[float],
        prediction_status: Optional[str] = None,
    ) -> None:
        """Record feature vector and prediction status from a monitoring cycle."""
        if feature_vector is not None and len(feature_vector) >= len(FEATURE_NAMES):
            clean = [float(v) if math.isfinite(float(v)) else 0.0 for v in feature_vector[:len(FEATURE_NAMES)]]
            self._history.append(clean)

        if prediction_status:
            key = str(prediction_status).upper()
            if key in self._status_counts:
                self._status_counts[key] += 1
            else:
                self._status_counts["UNKNOWN"] += 1

    def record_adwin_drift(
        self,
        switch_id: int,
        adwin_alerts: Sequence[Dict[str, Any]],
        timestamp: Optional[datetime] = None,
    ) -> Optional[DriftEvent]:
        """
        Record and format drift alerts from the existing ADWIN detector.
        """
        if not adwin_alerts:
            return None

        ts = ensure_utc(timestamp or utc_now()).isoformat()
        affected_features: List[str] = []
        max_mag = 0.0

        for alert in adwin_alerts:
            feat = str(alert.get("metric") or alert.get("feature") or "traffic_rate")
            if feat not in affected_features:
                affected_features.append(feat)
            mag = float(alert.get("magnitude") or alert.get("diff") or 1.0)
            if mag > max_mag:
                max_mag = mag

        event_id = f"drift_{int(datetime.now().timestamp() * 1000)}"
        event = DriftEvent(
            event_id=event_id,
            timestamp=ts,
            switch_id=switch_id,
            affected_features=affected_features,
            drift_status="DRIFT_DETECTED",
            magnitude=round(max_mag, 4),
            details={"alerts": list(adwin_alerts), "history_size": len(self._history)},
        )

        self._drift_events.append(event)
        self._last_drift_detected_at = utc_now()
        self._consecutive_drift_count += 1

        self._persist_event(event)
        logger.warning(
            "[DriftMonitor] ADWIN drift recorded on switch %d: %d affected features (%s)",
            switch_id,
            len(affected_features),
            ", ".join(affected_features),
        )
        return event

    def _persist_event(self, event: DriftEvent) -> None:
        """Append event to drift_events.jsonl."""
        try:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception as exc:
            logger.error("[DriftMonitor] Could not persist drift event: %s", exc)

    def get_feature_distribution_stats(self) -> Dict[str, Dict[str, float]]:
        """Compute rolling mean and std per feature across the buffered window."""
        if not self._history:
            return {}

        n_feats = len(FEATURE_NAMES)
        n_samples = len(self._history)
        stats: Dict[str, Dict[str, float]] = {}

        for j in range(n_feats):
            vals = [row[j] for row in self._history if j < len(row)]
            if not vals:
                continue
            mean_val = sum(vals) / n_samples
            var_val = sum((x - mean_val) ** 2 for x in vals) / max(1, n_samples - 1)
            std_val = math.sqrt(var_val)
            stats[FEATURE_NAMES[j]] = {
                "mean": round(mean_val, 4),
                "std": round(std_val, 4),
                "min": round(min(vals), 4),
                "max": round(max(vals), 4),
            }

        return stats

    def get_drift_status(self) -> Dict[str, Any]:
        """Summary for API / Dashboard."""
        return {
            "has_recent_drift": self._last_drift_detected_at is not None
            and (utc_now() - self._last_drift_detected_at).total_seconds() < 300,
            "last_drift_timestamp": self._last_drift_detected_at.isoformat() if self._last_drift_detected_at else None,
            "consecutive_drift_count": self._consecutive_drift_count,
            "total_drift_events": len(self._drift_events),
            "prediction_status_counts": dict(self._status_counts),
            "window_samples_buffered": len(self._history),
        }

    def get_recent_events(self, limit: int = 10) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._drift_events[-limit:]]

