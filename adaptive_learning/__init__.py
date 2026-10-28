"""
IntelliShield SDN — Adaptive Learning for Evolving Attacks (Novelty R9).

Monitors feature distributions and ADWIN concept drift, safely collects verified
traffic samples, trains candidate adaptation models, validates them against fixed
held-out benchmarks, and manages model promotion, versioning, and rollback.
"""

from adaptive_learning.drift_monitor import DriftMonitor, DriftEvent
from adaptive_learning.sample_buffer import VerifiedSampleBuffer
from adaptive_learning.model_updater import AdaptiveModelUpdater
from adaptive_learning.model_registry import AdaptiveModelRegistry
from adaptive_learning.service import AdaptiveLearningService, adaptive_service

__all__ = [
    "DriftMonitor",
    "DriftEvent",
    "VerifiedSampleBuffer",
    "AdaptiveModelUpdater",
    "AdaptiveModelRegistry",
    "AdaptiveLearningService",
    "adaptive_service",
]

