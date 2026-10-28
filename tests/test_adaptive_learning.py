"""
Unit and integration tests for Adaptive Learning for Evolving Attacks.
"""

import os
import shutil
import tempfile
import numpy as np
import pytest

from adaptive_learning.drift_monitor import DriftMonitor, DriftEvent
from adaptive_learning.sample_buffer import VerifiedSampleBuffer
from adaptive_learning.model_updater import AdaptiveModelUpdater
from adaptive_learning.model_registry import AdaptiveModelRegistry
from adaptive_learning.service import AdaptiveLearningService


@pytest.fixture
def temp_logs_dir():
    temp_dir = tempfile.mkdtemp(prefix="test_adaptive_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_drift_monitor_statistics(temp_logs_dir):
    log_file = os.path.join(temp_logs_dir, "test_drift.jsonl")
    monitor = DriftMonitor(window_size=20, log_path=log_file)

    for i in range(15):
        vec = [float(j + i) for j in range(15)]
        monitor.record_cycle_features(switch_id=1, feature_vector=vec, prediction_status="NORMAL")

    stats = monitor.get_feature_distribution_stats()
    assert len(stats) == 15
    assert "packet_rate_mean" in stats
    assert stats["packet_rate_mean"]["mean"] > 0.0

    status = monitor.get_drift_status()
    assert status["prediction_status_counts"]["NORMAL"] == 15
    assert status["window_samples_buffered"] == 15


def test_drift_monitor_adwin_alert_recording(temp_logs_dir):
    log_file = os.path.join(temp_logs_dir, "test_drift.jsonl")
    monitor = DriftMonitor(window_size=20, log_path=log_file)

    alerts = [{"metric": "packet_rate_mean", "magnitude": 2.5}]
    event = monitor.record_adwin_drift(switch_id=2, adwin_alerts=alerts)

    assert event is not None
    assert event.switch_id == 2
    assert "packet_rate_mean" in event.affected_features
    assert event.drift_status == "DRIFT_DETECTED"
    assert os.path.exists(log_file)

    recent = monitor.get_recent_events(limit=5)
    assert len(recent) == 1
    assert recent[0]["event_id"] == event.event_id


def test_sample_buffer_safety_gates():
    buffer = VerifiedSampleBuffer(max_normal_samples=10, max_attack_samples=5)
    valid_vec = [1.0] * 15

    # 1. Unverified sample without trusted source -> REJECTED
    res = buffer.add_sample(vector=valid_vec, label=0, source="ml_prediction", verified=False)
    assert res is False

    # 2. Verified sample -> ACCEPTED
    res2 = buffer.add_sample(vector=valid_vec, label=0, source="r7_verified", verified=True)
    assert res2 is True

    # 3. Trusted source without verified flag -> ACCEPTED
    res3 = buffer.add_sample(vector=valid_vec, label=1, source="ground_truth", verified=False)
    assert res3 is True

    # 4. Invalid label -> REJECTED
    res4 = buffer.add_sample(vector=valid_vec, label=99, source="ground_truth", verified=True)
    assert res4 is False

    stats = buffer.get_stats()
    assert stats["normal_samples_count"] == 1
    assert stats["attack_samples_count"] == 1
    assert stats["rejected_unverified_count"] == 1


def test_sample_buffer_bounded_capacity():
    buffer = VerifiedSampleBuffer(max_normal_samples=5, max_attack_samples=3)
    valid_vec = [2.0] * 15

    for _ in range(10):
        buffer.add_sample(vector=valid_vec, label=0, source="ground_truth")

    stats = buffer.get_stats()
    assert stats["normal_samples_count"] == 5  # Bounded to max_normal


def test_model_updater_and_safety_checks():
    updater = AdaptiveModelUpdater(min_f1=0.80, max_fpr=0.08)

    # Train on synthetic baseline
    cand_tree, scaler, train_time = updater.train_candidate(
        X_new=np.empty((0, 15)), y_new=np.empty((0,), dtype=int), include_anchor=True
    )
    assert train_time > 0.0

    metrics = updater.evaluate_model(cand_tree, scaler)
    assert metrics["accuracy"] >= 0.80
    assert metrics["f1_score"] >= 0.80
    assert metrics["false_positive_rate"] <= 0.08

    # Safety check passes
    passed, reason = updater.validate_candidate_safety(metrics)
    assert passed is True

    # Artificially fail safety check (e.g. low F1)
    failed_metrics = dict(metrics)
    failed_metrics["f1_score"] = 0.50
    passed_fail, reason_fail = updater.validate_candidate_safety(failed_metrics)
    assert passed_fail is False
    assert "below minimum safety threshold" in reason_fail


def test_model_registry_lifecycle_and_rollback(temp_logs_dir):
    registry = AdaptiveModelRegistry(registry_dir=temp_logs_dir)
    updater = AdaptiveModelUpdater()

    # Candidate 1
    m1, s1, _ = updater.train_candidate(np.empty((0, 15)), np.empty((0,), dtype=int))
    cand1 = registry.register_candidate(m1, s1, {"f1_score": 0.90}, algorithm="Tree_v1")
    p1 = registry.promote_candidate(cand1, reason="First version")

    assert registry.active_model.model_id == p1.model_id
    assert "v1.0-active" in p1.version_tag

    # Candidate 2
    m2, s2, _ = updater.train_candidate(np.empty((0, 15)), np.empty((0,), dtype=int))
    cand2 = registry.register_candidate(m2, s2, {"f1_score": 0.92}, algorithm="Tree_v2")
    p2 = registry.promote_candidate(cand2, reason="Second version")

    assert registry.active_model.model_id == p2.model_id
    assert registry.previous_model.model_id == p1.model_id

    # Rollback to Candidate 1
    restored, msg = registry.rollback()
    assert restored is not None
    assert restored.model_id == p1.model_id
    assert registry.active_model.model_id == p1.model_id


def test_adaptive_learning_service_end_to_end():
    service = AdaptiveLearningService(min_adaptation_interval_sec=0.0, min_normal_samples=5, min_attack_samples=5)
    valid_vec = [10.0] * 15

    # Feed verified samples
    for _ in range(6):
        service.add_verified_sample(valid_vec, label=0, source="ground_truth", verified=True)
    for _ in range(6):
        service.add_verified_sample(valid_vec, label=1, source="ground_truth", verified=True)

    # Trigger adaptation
    res = service.trigger_adaptation(force=True, reason="Unit test trigger")
    assert res["adapted"] is True
    assert res["status"] == "PROMOTED"
    assert "metrics" in res

    # Verify status
    status = service.get_status()
    assert status["registry"]["active_model"] is not None
    assert status["samples"]["normal_samples_count"] == 6
    assert status["samples"]["attack_samples_count"] == 6
