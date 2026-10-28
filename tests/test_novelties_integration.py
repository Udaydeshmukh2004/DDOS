"""
Comprehensive Integration Tests for IntelliShield SDN Three Core Research Novelties:
1. Adaptive Learning for Evolving Attacks (R9)
2. Zero-Day Attack Detection using Self-Supervised Learning (SSL - R2)
3. Self-Evolving Detection using Online AutoML (R1)
"""

import math
import os
import shutil
import tempfile
import numpy as np
import pytest
from fastapi.testclient import TestClient

from shared_contracts.enums import DetectionDecision, DetectorHealth, DetectorType
from shared_contracts.models import DetectorResult
from shared_contracts.timeutil import utc_now
from ssl_zero_day.autoencoder import SSLAutoencoder
from ssl_zero_day.detector import SSLZeroDayDetector
from ssl_zero_day.threshold import SSLThresholdCalibrator
from adaptive_learning.drift_monitor import DriftMonitor
from adaptive_learning.sample_buffer import VerifiedSampleBuffer
from adaptive_learning.model_updater import AdaptiveModelUpdater
from adaptive_learning.model_registry import AdaptiveModelRegistry
from adaptive_learning.service import AdaptiveLearningService
from online_automl.service import OnlineAutoMLService
from fusion.engine import CollaborativeFusionEngine
from fusion.adapters import adapt_ssl_result
from dashboard.api import app


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="test_novelties_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_feature_preprocessing_consistency():
    """Verify 15-D vector sanitization, NaN/Inf handling, and boundary guarantees."""
    from ssl_zero_day.feature_window import sanitize_15d_vector, validate_15d_vector

    # Vector with NaN, Inf, and strings
    dirty = [10.0, float("nan"), float("inf"), -float("inf"), 5.0]
    clean = sanitize_15d_vector(dirty)
    assert len(clean) == 15
    assert clean[0] == 10.0
    assert clean[1] == 0.0  # NaN replaced with 0.0
    assert clean[2] == 0.0  # Inf replaced with 0.0
    assert clean[3] == 0.0  # -Inf replaced with 0.0
    assert all(math.isfinite(x) for x in clean)
    assert validate_15d_vector(clean) is True


def test_ssl_training_and_anomaly_scoring(temp_dir):
    """Verify SSL autoencoder learns baseline representations without labels."""
    detector = SSLZeroDayDetector(models_dir=temp_dir, auto_load=False)
    rng = np.random.RandomState(42)

    # 50 normal samples
    X_normal = []
    for _ in range(50):
        vec = [float(rng.uniform(10.0, 50.0)) for _ in range(15)]
        X_normal.append(vec)

    ok = detector.train_normal(X_normal, persist=True)
    assert ok is True
    assert detector.is_ready is True
    assert detector.calibrator.is_calibrated is True

    # Normal sample prediction
    res_norm = detector.predict_result(X_normal[0])
    assert res_norm.decision in (DetectionDecision.NORMAL, DetectionDecision.NONE)
    assert res_norm.health == DetectorHealth.SUCCESS
    assert res_norm.score is not None

    # Novel unfamiliar attack sample with high values
    attack_vec = [100000.0] * 15
    res_atk = detector.predict_result(attack_vec)
    assert res_atk.score > res_norm.score
    assert res_atk.decision in (DetectionDecision.ATTACK, DetectionDecision.SUSPICIOUS)
    if res_atk.decision == DetectionDecision.ATTACK:
        assert res_atk.attack_hint == "ZERO_DAY_ANOMALY"


def test_ssl_threshold_calibration():
    """Verify calibration separates normal baseline from anomalous errors."""
    calibrator = SSLThresholdCalibrator()
    normal_errors = [0.01, 0.015, 0.012, 0.018, 0.014, 0.011, 0.016]
    calibrator.calibrate(normal_errors, quantile=0.90, k_std=2.0)

    assert calibrator.is_calibrated is True
    assert calibrator.normal_threshold > 0.0
    assert calibrator.attack_threshold > calibrator.normal_threshold

    # Low error -> NORMAL
    dec_norm, _ = calibrator.classify_score(0.005)
    assert dec_norm == DetectionDecision.NORMAL
    # High error -> ATTACK
    dec_atk, _ = calibrator.classify_score(5.0)
    assert dec_atk == DetectionDecision.ATTACK


def test_hybrid_decision_policy_in_fusion():
    """Verify that SSL results are properly ingested as PRIMARY evidence in R6 fusion."""
    fusion_engine = CollaborativeFusionEngine()

    ssl_res = DetectorResult(
        detector=DetectorType.SSL,
        timestamp=utc_now(),
        health=DetectorHealth.SUCCESS,
        decision=DetectionDecision.ATTACK,
        confidence=0.88,
        score=2.45,
        threshold=0.50,
        attack_hint="ZERO_DAY_ANOMALY",
        evidence={"role": "PRIMARY_DETECTION"},
    )

    fused = fusion_engine.fuse(
        detector_results=[ssl_res],
        switch_id=1,
    )
    assert fused is not None
    assert fused.decision in (DetectionDecision.ATTACK, DetectionDecision.SUSPICIOUS)
    assert "SSL" in fused.participating


def test_drift_detection_and_sample_collection(temp_dir):
    """Verify ADWIN drift ingestion and safety-gated sample buffering."""
    service = AdaptiveLearningService(min_adaptation_interval_sec=0.0)

    # Process normal cycles
    vec = [10.0] * 15
    service.process_monitoring_cycle(switch_id=1, feature_vector=vec, prediction_status="NORMAL")

    # Unverified attack -> must be rejected
    accepted = service.add_verified_sample(vec, label=1, source="model_guess", verified=False)
    assert accepted is False

    # Confirmed R7 verified attack -> accepted
    accepted_r7 = service.add_verified_sample(vec, label=1, source="r7_verified", verified=True)
    assert accepted_r7 is True

    # Confirmed R7 verified normal -> accepted
    accepted_norm = service.add_verified_sample(vec, label=0, source="r7_verified", verified=True)
    assert accepted_norm is True

    stats = service.sample_buffer.get_stats()
    assert stats["normal_samples_count"] >= 1
    assert stats["attack_samples_count"] >= 1


def test_candidate_training_and_comparison():
    """Verify candidate model validation and safety check against active model."""
    updater = AdaptiveModelUpdater(min_f1=0.80, max_fpr=0.05)
    model, scaler, train_time = updater.train_candidate(np.empty((0, 15)), np.empty((0,), dtype=int))
    assert train_time > 0.0

    metrics = updater.evaluate_model(model, scaler)
    passed, reason = updater.validate_candidate_safety(metrics)
    assert passed is True


def test_model_promotion_and_rollback(temp_dir):
    """Verify candidate promotion, version tagging, and automated rollback."""
    registry = AdaptiveModelRegistry(registry_dir=temp_dir)
    updater = AdaptiveModelUpdater()

    m1, s1, _ = updater.train_candidate(np.empty((0, 15)), np.empty((0,), dtype=int))
    cand1 = registry.register_candidate(m1, s1, {"f1_score": 0.88})
    p1 = registry.promote_candidate(cand1, reason="Base v1")
    assert registry.active_model.model_id == p1.model_id

    m2, s2, _ = updater.train_candidate(np.empty((0, 15)), np.empty((0,), dtype=int))
    cand2 = registry.register_candidate(m2, s2, {"f1_score": 0.91})
    p2 = registry.promote_candidate(cand2, reason="Promote v2")
    assert registry.active_model.model_id == p2.model_id

    # Rollback to v1
    restored, reason = registry.rollback()
    assert restored is not None
    assert restored.model_id == p1.model_id


def test_online_automl_service_execution():
    """Verify Online AutoML executes candidate suite, evaluates metrics, and chooses champion."""
    automl = OnlineAutoMLService()
    report = automl.run_automl_pipeline(force=True)
    assert report["ran"] is True
    assert report["candidates_evaluated"] > 0
    assert "champion_selected" in report

    status = automl.get_status()
    assert "candidates" in status
    assert "version_history" in status


def test_api_endpoints_integration():
    """Verify FastAPI endpoints for AutoML, Adaptive Learning, and SSL Zero-Day."""
    client = TestClient(app)

    # 1. AutoML status
    r_auto = client.get("/api/automl/status")
    assert r_auto.status_code == 200
    assert "is_running" in r_auto.json()

    # 2. Adaptive Learning status
    r_adapt = client.get("/api/adaptive-learning/status")
    assert r_adapt.status_code == 200
    assert "drift" in r_adapt.json()
    assert "samples" in r_adapt.json()
    assert "registry" in r_adapt.json()

    # 3. SSL status
    r_ssl = client.get("/api/ssl/status")
    assert r_ssl.status_code == 200
    assert "ready" in r_ssl.json()

    # 4. SSL score endpoint
    vec = [20.0] * 15
    r_score = client.post("/api/ssl/score", json={"vector": vec})
    assert r_score.status_code == 200
    res_json = r_score.json()
    assert "decision" in res_json
    assert "mse_score" in res_json


def test_malformed_and_insufficient_data_resilience():
    """Verify that malformed inputs and insufficient datasets fail safely without raising uncaught exceptions."""
    updater = AdaptiveModelUpdater()
    # Empty inputs handled cleanly
    m, s, _ = updater.train_candidate(np.empty((0, 15)), np.empty((0,), dtype=int), include_anchor=True)
    metrics = updater.evaluate_model(m, s)
    assert metrics["accuracy"] >= 0.0

    buffer = VerifiedSampleBuffer()
    # Malformed vector length < 15
    assert buffer.add_sample([1.0, 2.0], label=0, source="ground_truth") is False
    # None vector
    assert buffer.add_sample(None, label=0, source="ground_truth") is False


def test_adaptive_learning_process_monitoring_cycle_and_gate():
    """Verify process_monitoring_cycle triggers candidate training on ADWIN drift and integrates with deployment gate."""
    from ml_models.deployment_gate import ModelDeploymentGate

    service = AdaptiveLearningService(
        min_adaptation_interval_sec=0.0,
        min_normal_samples=5,
        min_attack_samples=3,
    )
    gate = ModelDeploymentGate(allow_synthetic_promotion=False, min_f1_threshold=0.50)

    deployed_versions = []
    gate.register_on_deploy(lambda est, scl, src, ver: deployed_versions.append((src, ver)))

    # Register gate callback on service
    service.register_on_model_promoted(
        lambda est, scl: gate.request_deployment(
            source="adaptive_learning",
            version=service.registry.active_model.version_tag if service.registry.active_model else "al_v1",
            estimator=est,
            scaler=scl,
            metrics=service.registry.active_model.metrics if service.registry.active_model else {},
            is_synthetic=False,
            provenance="r7_verified_live_traffic",
        )
    )

    # 1. Feed verified samples
    for i in range(10):
        service.add_verified_sample([10.0 + i] * 15, label=0, source="r7_verified", verified=True)
    for i in range(5):
        service.add_verified_sample([5000.0 + i] * 15, label=1, source="r7_verified", verified=True)

    # 2. Cycle without drift -> No adaptation
    res_no_drift = service.process_monitoring_cycle(
        switch_id=1,
        feature_vector=[15.0] * 15,
        prediction_status="NORMAL",
        adwin_alerts=[],
    )
    assert res_no_drift is None

    # 3. Cycle with ADWIN drift alerts -> Triggers adaptation & deploys through gate
    adwin_alerts = [{"metric_name": "byte_rate_mean", "dpid": 1, "value": 45000.0}]
    res_drift = service.process_monitoring_cycle(
        switch_id=1,
        feature_vector=[5000.0] * 15,
        prediction_status="ATTACK",
        adwin_alerts=adwin_alerts,
    )
    assert res_drift is not None
    assert res_drift.get("adapted") is True
    assert gate.active_source == "adaptive_learning"
    assert len(deployed_versions) >= 1


def test_shared_deployment_gate_synthetic_guard_and_rollback():
    """Verify shared deployment gate blocks synthetic models from live deployment and supports rollback."""
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.preprocessing import StandardScaler
    from ml_models.deployment_gate import ModelDeploymentGate

    gate = ModelDeploymentGate(allow_synthetic_promotion=False, min_f1_threshold=0.60)

    scaler = StandardScaler()
    X = np.random.randn(20, 15)
    y = np.array([0] * 10 + [1] * 10)
    scaler.fit(X)
    tree = DecisionTreeClassifier()
    tree.fit(scaler.transform(X), y)

    # 1. Attempt deployment of synthetic benchmark candidate -> Must be rejected
    ok, reason = gate.request_deployment(
        source="online_automl",
        version="automl_synth_v1",
        estimator=tree,
        scaler=scaler,
        metrics={"f1_score": 0.95},
        is_synthetic=True,
        provenance="synthetic_benchmark_generator",
    )
    assert ok is False
    assert "SYNTHETIC" in reason

    # 2. Attempt deployment of real network candidate -> Must succeed
    ok_real, reason_real = gate.request_deployment(
        source="online_automl",
        version="automl_real_v1",
        estimator=tree,
        scaler=scaler,
        metrics={"f1_score": 0.92},
        is_synthetic=False,
        provenance="real_csv:logs/ml_features.csv",
    )
    assert ok_real is True
    assert gate.active_version == "automl_real_v1"

    # 3. Next promotion from adaptive learning
    tree2 = DecisionTreeClassifier()
    tree2.fit(scaler.transform(X), y)
    ok_al, _ = gate.request_deployment(
        source="adaptive_learning",
        version="al_v2",
        estimator=tree2,
        scaler=scaler,
        metrics={"f1_score": 0.94},
        is_synthetic=False,
        provenance="r7_verified_live_traffic",
    )
    assert ok_al is True
    assert gate.active_version == "al_v2"

    # 4. Atomic Rollback
    rolled_back, roll_msg = gate.rollback()
    assert rolled_back is True
    assert gate.active_version == "automl_real_v1"
    assert gate.active_source == "online_automl"

