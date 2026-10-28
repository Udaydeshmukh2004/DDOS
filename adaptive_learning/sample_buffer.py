"""
Verified Sample Buffer for Adaptive Learning.

Safety controls:
1. Rejects unverified traffic predictions (never trains on raw model inferences).
2. Requires explicit verification flags (from R7 Multi-Stage Verification, ground truth, or controlled simulation).
3. Enforces bounded queues to prevent memory leaks (FIFO eviction).
4. Provides class-balanced sampling for candidate model adaptation.
"""

from __future__ import annotations

import logging
import math
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np

from shared_contracts.timeutil import utc_now
from ml_models.feature_builder import FEATURE_NAMES

logger = logging.getLogger("intellishield.adaptive_learning.sample_buffer")

N_FEATURES = len(FEATURE_NAMES)  # 15


@dataclass
class VerifiedSample:
    vector: List[float]
    label: int  # 0 = NORMAL, 1 = ATTACK
    source: str  # "ground_truth", "simulation", "r7_verified", "operator_verified"
    verified: bool
    confidence: float
    timestamp: datetime


class VerifiedSampleBuffer:
    """
    Bounded, safety-gated buffer storing only validated traffic observations.
    """

    def __init__(
        self,
        max_normal_samples: int = 1000,
        max_attack_samples: int = 500,
    ) -> None:
        self.max_normal = max_normal_samples
        self.max_attack = max_attack_samples
        self._normal_buffer: Deque[VerifiedSample] = deque(maxlen=max_normal_samples)
        self._attack_buffer: Deque[VerifiedSample] = deque(maxlen=max_attack_samples)
        self._rejected_unverified_count: int = 0
        self._total_collected: int = 0

    def add_sample(
        self,
        vector: Sequence[float],
        label: int,
        source: str,
        verified: bool = False,
        confidence: float = 1.0,
        timestamp: Optional[datetime] = None,
    ) -> bool:
        """
        Add a sample to the buffer with strict safety checks.

        Returns True if accepted, False if rejected.
        """
        # Safety Gate 1: Must be explicitly verified or from trusted ground-truth/simulation
        trusted_sources = {"ground_truth", "simulation", "controlled_test", "operator_verified"}
        if source not in trusted_sources and not verified:
            self._rejected_unverified_count += 1
            logger.debug(
                "[VerifiedSampleBuffer] Rejected unverified sample from source '%s'",
                source,
            )
            return False

        # Safety Gate 2: Label must be binary (0 or 1)
        if label not in (0, 1):
            logger.warning("[VerifiedSampleBuffer] Rejected sample with invalid label %s", label)
            return False

        # Safety Gate 3: Feature vector validation & sanitization
        if vector is None or len(vector) < N_FEATURES:
            return False

        clean_vec: List[float] = []
        for val in vector[:N_FEATURES]:
            try:
                fval = float(val)
                clean_vec.append(fval if math.isfinite(fval) else 0.0)
            except (ValueError, TypeError):
                clean_vec.append(0.0)

        sample = VerifiedSample(
            vector=clean_vec,
            label=label,
            source=source,
            verified=verified or (source in trusted_sources),
            confidence=max(0.0, min(1.0, float(confidence))),
            timestamp=timestamp or utc_now(),
        )

        if label == 0:
            self._normal_buffer.append(sample)
        else:
            self._attack_buffer.append(sample)

        self._total_collected += 1
        return True

    def get_training_dataset(
        self,
        min_normal: int = 20,
        min_attack: int = 10,
    ) -> Optional[Tuple[np.ndarray, np.ndarray]]:
        """
        Return (X, y) numpy arrays if sufficient verified samples exist for both classes.
        Returns None if thresholds are not met.
        """
        if len(self._normal_buffer) < min_normal or len(self._attack_buffer) < min_attack:
            return None

        X: List[List[float]] = []
        y: List[int] = []

        for s in self._normal_buffer:
            X.append(s.vector)
            y.append(0)

        for s in self._attack_buffer:
            X.append(s.vector)
            y.append(1)

        return np.array(X, dtype=float), np.array(y, dtype=int)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "normal_samples_count": len(self._normal_buffer),
            "attack_samples_count": len(self._attack_buffer),
            "max_normal_capacity": self.max_normal,
            "max_attack_capacity": self.max_attack,
            "total_samples_collected": self._total_collected,
            "rejected_unverified_count": self._rejected_unverified_count,
            "is_sufficient_for_training": len(self._normal_buffer) >= 20 and len(self._attack_buffer) >= 10,
        }

    def clear(self) -> None:
        self._normal_buffer.clear()
        self._attack_buffer.clear()

