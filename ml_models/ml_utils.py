"""
================================================================================
IntelliShield SDN — Phase 4: ML-Based Anomaly Detection
================================================================================

File        : ml_models/ml_utils.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 4 — ML Anomaly Detection

Description:
    Low-level utility helpers shared across all ml_models modules.
    Handles safe arithmetic, normalisation, label encoding, and
    feature vector validation. Keeps math isolated and testable.

================================================================================
"""

import math
import logging
from typing import List, Optional

logger = logging.getLogger("intellishield.ml_utils")


# ─── Safe Arithmetic ──────────────────────────────────────────────────────────

def safe_mean(values: list) -> float:
    """Return arithmetic mean, or 0.0 for empty / all-None/NaN lists."""
    if not values:
        return 0.0
    vals = [
        float(v) for v in values
        if v is not None and not isinstance(v, bool) and isinstance(v, (int, float))
        and not (math.isnan(v) or math.isinf(v))
    ]
    return sum(vals) / len(vals) if vals else 0.0


def safe_max(values: list) -> float:
    """Return max value, or 0.0 for empty / all-None/NaN lists."""
    if not values:
        return 0.0
    vals = [
        float(v) for v in values
        if v is not None and not isinstance(v, bool) and isinstance(v, (int, float))
        and not (math.isnan(v) or math.isinf(v))
    ]
    return max(vals) if vals else 0.0


def safe_min(values: list) -> float:
    """Return min value, or 0.0 for empty / all-None/NaN lists."""
    if not values:
        return 0.0
    vals = [
        float(v) for v in values
        if v is not None and not isinstance(v, bool) and isinstance(v, (int, float))
        and not (math.isnan(v) or math.isinf(v))
    ]
    return min(vals) if vals else 0.0


def safe_divide(a: float, b: float, default: float = 0.0) -> float:
    """Return a/b safely, returning `default` when b == 0."""
    return a / b if b != 0 else default


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp value to [lo, hi]."""
    return max(lo, min(hi, value))


# ─── Feature Validation ───────────────────────────────────────────────────────

def validate_vector(vector: list, expected_len: int) -> bool:
    """
    Check that a feature vector has the correct length, numeric types, and no NaN/Inf.

    Args:
        vector      : Feature list.
        expected_len: Expected number of dimensions.

    Returns:
        bool: True if valid.
    """
    if vector is None or not hasattr(vector, "__len__"):
        logger.warning("[validate_vector] Non-sequence vector passed: %s", type(vector))
        return False
    if len(vector) != expected_len:
        logger.warning("[validate_vector] Length mismatch: got %d, expected %d",
                       len(vector), expected_len)
        return False
    for v in vector:
        if v is None or isinstance(v, bool) or not isinstance(v, (int, float)):
            logger.warning("[validate_vector] Non-numeric/None item in vector: %r", v)
            return False
        if math.isnan(v) or math.isinf(v):
            logger.warning("[validate_vector] NaN/Inf in vector: %r", v)
            return False
    return True


def sanitize_vector(vector: list) -> list:
    """Replace NaN, Inf, None, and non-numeric items with 0.0 in a feature vector."""
    if vector is None:
        return []
    result = []
    for v in vector:
        if v is None or isinstance(v, bool):
            result.append(0.0)
        elif isinstance(v, (int, float)):
            if math.isnan(v) or math.isinf(v):
                result.append(0.0)
            else:
                result.append(float(v))
        else:
            try:
                num = float(v)
                result.append(0.0 if (math.isnan(num) or math.isinf(num)) else num)
            except (ValueError, TypeError):
                result.append(0.0)
    return result


# ─── Label Utilities ──────────────────────────────────────────────────────────

LABEL_MAP = {
    0 : "NORMAL",
    1 : "ATTACK",
    -1: "UNKNOWN",
}

LABEL_REVERSE = {v: k for k, v in LABEL_MAP.items()}


def label_to_str(label: int) -> str:
    """Convert integer label to string name."""
    return LABEL_MAP.get(label, "UNKNOWN")


def str_to_label(name: str) -> int:
    """Convert string label name to integer."""
    return LABEL_REVERSE.get(name.upper(), -1)


# ─── Min-Max Normalization ────────────────────────────────────────────────────

def minmax_normalize(X: List[List[float]]) -> List[List[float]]:
    """
    Apply min-max normalization column-wise to bring all features to [0, 1].

    Each column is scaled independently: x_norm = (x - min) / (max - min).
    Used when sklearn StandardScaler is not available (stdlib-only fallback).

    Args:
        X: List of feature vectors (rows).

    Returns:
        Normalized feature matrix.
    """
    if not X:
        return X

    n_features = len(X[0])
    mins = [safe_min([row[j] for row in X]) for j in range(n_features)]
    maxs = [safe_max([row[j] for row in X]) for j in range(n_features)]

    result = []
    for row in X:
        norm_row = []
        for j in range(n_features):
            span = maxs[j] - mins[j]
            norm_row.append(safe_divide(row[j] - mins[j], span, default=0.0))
        result.append(norm_row)
    return result


# ─── Confidence Formatting ────────────────────────────────────────────────────

def format_confidence(score: float) -> str:
    """Format an anomaly score as a human-readable confidence string."""
    pct = clamp(score * 100, 0.0, 100.0)
    return f"{pct:.1f}%"


def anomaly_score_to_status(score: float,
                              normal_threshold: float = 0.3,
                              attack_threshold: float = 0.6) -> str:
    """
    Map a continuous anomaly score to a 3-class status string.

    Args:
        score             : Anomaly score in [0, 1]. Higher = more anomalous.
        normal_threshold  : Below this → NORMAL.
        attack_threshold  : Above this → ATTACK.

    Returns:
        str: "NORMAL" / "SUSPICIOUS" / "ATTACK"
    """
    if score < normal_threshold:
        return "NORMAL"
    elif score < attack_threshold:
        return "SUSPICIOUS"
    else:
        return "ATTACK"
