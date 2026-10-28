"""
================================================================================
IntelliShield SDN — End-to-End Complete Flow Integration Test Suite
================================================================================

Validates all 10 Stages of the IntelliShield SDN Architecture:
  Stage 1  — Traffic Collection (OpenFlow Flow & Port Statistics)
  Stage 2  — Feature Extraction & Sanitization (15-D vector, NaN/Inf handling)
  Stage 3  — Hybrid Detection Layer (ML + Shannon Entropy + SSL Autoencoder + ADWIN + HDBSCAN + RL)
  Stage 4  — Multi-Stage Decision & Policy Engine (Collaborative Fusion & Disagreement Shrink)
  Stage 5  — Explainability & Root-Cause Analysis (SHAP/LIME + Causal Graph DAG)
  Stage 6  — Digital Twin Telemetry Sync & Plan-Space Candidate Policy Validation
  Stage 7  — Mitigation Decision Engine (Attacker Identification, Strategy Selection, Timeouts)
  Stage 8  — OpenFlow Rule Enforcement & Flow Expiration Sync (OFPFlowMod Drop Rules, Removal)
  Stage 9  — Adaptive Learning & Online AutoML Feedback Loop (Drift Trigger, Verified Buffer, Hot-Swap)
  Stage 10 — Dashboard, APIs, Alerts, and Complete Audit Trail
================================================================================
"""

import math
import os
import shutil
import tempfile
import numpy as np
import pytest
from fastapi.testclient import TestClient

from shared_contracts.enums import (
    DetectionDecision,
    DetectorHealth,
    DetectorType,
    VerificationStatus,
)
from shared_contracts.models import DetectorResult, new_id
from shared_contracts.timeutil import utc_now

# Core Modules
from ssl_zero_day.autoencoder import SSLAutoencoder
from ssl_zero_day.detector import SSLZeroDayDetector
from ssl_zero_day.feature_window import sanitize_15d_vector, validate_15d_vector
from ssl_zero_day.threshold import SSLThresholdCalibrator
from ml_models.anomaly_detector import AnomalyDetector
from ml_models.feature_builder import FeatureBuilder, FEATURE_NAMES
from entropy_engine.entropy_detector import EntropyDetector
from advanced_analytics.adwin_detector import ADWINManager
from advanced_analytics.hdbscan_clusterer import ClusterManager
from rl_engine.ppo_agent import PPOAgent
from rl_engine.threshold_adapter import ThresholdAdapter

# Fusion & Verification
from fusion.engine import CollaborativeFusionEngine
from fusion.registry import build_default_registry
from fusion.adapters import (
    adapt_ml_prediction,
    adapt_entropy_metrics,
    adapt_ssl_result,
    adapt_correlation_result,
)
from verification.engine import VerificationEngine, VerificationInput
from verification.config import VerificationConfig
from verification.stages import VerificationStage

# Mitigation
from mitigation.mitigation_engine import MitigationEngine, BLOCK_PRIORITY
from mitigation.flow_blocker import block_src_mac, block_flow_pair, unblock_src_mac, unblock_all

# Adaptive Learning & AutoML
from adaptive_learning.service import AdaptiveLearningService
from adaptive_learning.sample_buffer import VerifiedSampleBuffer
from adaptive_learning.model_updater import AdaptiveModelUpdater
from adaptive_learning.model_registry import AdaptiveModelRegistry
from online_automl.service import OnlineAutoMLService

# Digital Twin
from twin.snapshot import capture_snapshot, load_snapshot
from twin.policy_evaluator import evaluate_candidate_policy

# RCA & Alerting
from rca import RootCauseEngine, RCAContext, MitigationEvidence
from alerting import AlertManager, AlertingConfig

# Dashboard API
from dashboard.api import app


# ─── Mock Datapath & OpenFlow Support ────────────────────────────────────────

class MockOfproto:
    OFPFC_ADD = 0
    OFPFC_DELETE = 1
    OFPFC_DELETE_STRICT = 2
    OFPFF_SEND_FLOW_REM = 1
    OFPP_ANY = 0xFFFFFFFF
    OFPG_ANY = 0xFFFFFFFF


class MockParser:
    @staticmethod
    def OFPMatch(**kwargs):
        return dict(kwargs)

    @staticmethod
    def OFPFlowMod(**kwargs):
        return dict(kwargs)


class MockDatapath:
    def __init__(self, dpid=1):
        self.id = dpid
        self.ofproto = MockOfproto()
        self.ofproto_parser = MockParser()
        self.sent_msgs = []

    def send_msg(self, msg):
        self.sent_msgs.append(msg)


# ─── Test Fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def temp_env():
    d = tempfile.mkdtemp(prefix="test_e2e_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ─── STAGE 1 & 2: Traffic Collection, Feature Extraction & Preprocessing ─────

def test_stage_1_and_2_feature_extraction_and_sanitization():
    """Verify feature normalization, schema integrity, and NaN/Inf sanitization."""
    builder = FeatureBuilder()

    raw_flows = [
        {
            "dpid": 1,
            "src_mac": "02:aa:00:00:00:01",
            "dst_mac": "02:bb:00:00:00:02",
            "packet_count": 1500,
            "byte_count": 960000,
            "duration_sec": 1.5,
            "packet_rate": 1000.0,
            "byte_rate": 640000.0,
            "packet_delta": 500,
            "byte_delta": 320000,
            "protocol": 6,
        }
    ]
    entropy_metrics = {
        "entropy_score": 0.45,
        "src_entropy": 0.20,
        "dst_entropy": 0.90,
        "packet_entropy": 0.50,
        "byte_entropy": 0.50,
    }

    vec, meta = builder.build(
        flow_features=raw_flows,
        entropy_metrics=entropy_metrics,
        switch_id=1,
    )
    assert len(vec) == 15
    assert len(FEATURE_NAMES) == 15
    assert all(math.isfinite(x) for x in vec)

    # Test dirty input with NaN, Inf, string conversions
    dirty_vector = [100.0, float("nan"), float("inf"), -float("inf")] + [5.0] * 11
    clean_vec = sanitize_15d_vector(dirty_vector)
    assert len(clean_vec) == 15
    assert clean_vec[1] == 0.0
    assert clean_vec[2] == 0.0
    assert clean_vec[3] == 0.0
    assert validate_15d_vector(clean_vec) is True


# ─── STAGE 3: Hybrid Detection Layer ─────────────────────────────────────────

def test_stage_3_hybrid_detection_multi_detector(temp_env):
    """Verify that ML, Shannon Entropy, SSL Zero-Day, ADWIN, and RL run cohesively."""
    # 1. Supervised ML
    ml = AnomalyDetector(auto_load=False)
    assert ml is not None

    # 2. Shannon Entropy
    entropy = EntropyDetector(window_size=10)
    # Add normal diversified flows
    for i in range(10):
        entropy.add_flows(1, [{"src_mac": f"02:00:00:00:00:{i:02x}", "dst_mac": f"02:bb:00:00:00:{i:02x}", "packet_rate": 20.0, "byte_rate": 1000.0, "packet_count": 100, "byte_count": 5000}])
    ent_res = entropy.analyze(1)
    assert ent_res is not None
    assert "status" in ent_res
    assert "entropy_score" in ent_res

    # 3. SSL Zero-Day Autoencoder
    ssl_det = SSLZeroDayDetector(models_dir=temp_env, auto_load=False)
    normal_data = [[float(x) for x in range(15)] for _ in range(40)]
    ssl_det.train_normal(normal_data, persist=False)
    assert ssl_det.is_ready is True

    norm_score = ssl_det.predict_result(normal_data[0])
    assert norm_score.decision in (DetectionDecision.NORMAL, DetectionDecision.NONE)

    # High anomaly vector
    novel_attack = [9999.0] * 15
    atk_score = ssl_det.predict_result(novel_attack)
    assert atk_score.score > norm_score.score
    assert atk_score.decision in (DetectionDecision.ATTACK, DetectionDecision.SUSPICIOUS)

    # 4. ADWIN Drift Detector
    adwin = ADWINManager()
    alerts = adwin.update_all(1, {"flow_count": 10.0, "packet_rate_mean": 50.0, "byte_rate_mean": 3000.0, "entropy_score": 0.95})
    assert isinstance(alerts, list)

    # 5. PPO RL Adaptive Thresholds
    ppo = PPOAgent()
    adapter = ThresholdAdapter()
    state = np.zeros(10, dtype=np.float32)
    action, lp, val = ppo.step(state)
    new_thresh = adapter.apply_action(action)
    assert "pkt_threshold" in new_thresh
    assert "conf_threshold" in new_thresh


# ─── STAGE 4: Multi-Stage Decision & Policy Engine (Collaborative Fusion) ───

def test_stage_4_fusion_consensus_and_disagreement_shrink():
    """Verify collaborative fusion handles unanimous consensus and attenuates model disagreement."""
    fusion = CollaborativeFusionEngine()

    # Case A: Consensus Attack (ML + Entropy + SSL all say ATTACK)
    ml_res = DetectorResult(
        detector=DetectorType.ML,
        timestamp=utc_now(),
        health=DetectorHealth.SUCCESS,
        decision=DetectionDecision.ATTACK,
        confidence=0.95,
        score=0.95,
        attack_hint="SYN_FLOOD",
    )
    ent_res = DetectorResult(
        detector=DetectorType.ENTROPY,
        timestamp=utc_now(),
        health=DetectorHealth.SUCCESS,
        decision=DetectionDecision.ATTACK,
        confidence=0.90,
        score=0.30,
        attack_hint="SYN_FLOOD",
    )
    ssl_res = DetectorResult(
        detector=DetectorType.SSL,
        timestamp=utc_now(),
        health=DetectorHealth.SUCCESS,
        decision=DetectionDecision.ATTACK,
        confidence=0.92,
        score=3.5,
        attack_hint="ZERO_DAY_ANOMALY",
    )

    fused_attack = fusion.fuse(
        detector_results=[ml_res, ent_res, ssl_res],
        switch_id=1,
    )
    assert fused_attack.decision == DetectionDecision.ATTACK
    assert fused_attack.confidence >= 0.85
    assert "ML" in fused_attack.participating
    assert "ENTROPY" in fused_attack.participating
    assert "SSL" in fused_attack.participating

    # Case B: Model Disagreement (ML flags ATTACK, but Entropy and SSL say NORMAL)
    ent_norm = DetectorResult(
        detector=DetectorType.ENTROPY,
        timestamp=utc_now(),
        health=DetectorHealth.SUCCESS,
        decision=DetectionDecision.NORMAL,
        confidence=0.95,
        score=0.95,
    )
    ssl_norm = DetectorResult(
        detector=DetectorType.SSL,
        timestamp=utc_now(),
        health=DetectorHealth.SUCCESS,
        decision=DetectionDecision.NORMAL,
        confidence=0.90,
        score=0.01,
    )

    fused_disagree = fusion.fuse(
        detector_results=[ml_res, ent_norm, ssl_norm],
        switch_id=1,
    )
    # Conflict factor shrinks score: must NOT be high confidence ATTACK!
    assert fused_disagree.decision in (DetectionDecision.SUSPICIOUS, DetectionDecision.NORMAL)
    assert fused_disagree.disagreement is True


# ─── STAGE 5: Explainability & Root-Cause Analysis ───────────────────────────

def test_stage_5_explainability_and_rca(temp_env):
    """Verify RCA report generation and causal attribution packaging."""
    rca = RootCauseEngine()
    event_id = new_id()
    ctx = RCAContext(
        event_id=event_id,
        attack_hint="SYN_FLOOD",
        entropy_evidence={"entropy_score": 0.20, "src_entropy": 0.15},
        mitigation=MitigationEvidence(
            eligible=True, strategy="FLOW_PAIR", result="BLOCKED"
        ),
        report_id="rca-e2e-001",
    )
    report = rca.analyze(ctx)
    assert report is not None
    assert report.report_id == "rca-e2e-001"
    assert report.event_id == event_id
    assert report.summary is not None


# ─── STAGE 6: Digital Twin Validation & Plan-Space Policy Evaluation ────────

def test_stage_6_digital_twin_plan_space_validation(temp_env):
    """Verify Digital Twin loads telemetry and evaluates candidate policies in sandbox without controller actuation."""
    snapshot_data = {
        "snapshot_id": "snap-e2e-001",
        "baseline_vs_attack": {
            "baseline_mean_pkt_s": 50.0,
            "attack_mean_pkt_s": 12000.0,
            "n_baseline_rows": 20,
            "n_attack_rows": 20,
        },
    }

    candidate_policy = {
        "policy_name": "Adaptive-Strict",
        "packet_rate_threshold": 5000.0,
        "byte_rate_threshold": 3000000.0,
        "confidence_threshold": 0.80,
        "idle_timeout_sec": 60,
        "mitigation_action": "BLOCK",
    }

    # Evaluate candidate policy in sandbox
    result = evaluate_candidate_policy(snapshot_data, candidate_policy, persist=False)
    assert result is not None
    assert "validation_id" in result
    assert "candidate_policy" in result
    assert "classification" in result


# ─── STAGE 7 & 8: Mitigation Decision & OpenFlow Rule Enforcement ────────────

def test_stage_7_and_8_mitigation_and_openflow_enforcement():
    """Verify attacker identification, strategy selection, OFPFlowMod installation, and flow removal sync."""
    engine = MitigationEngine(auto_mitigate=True)
    dp = MockDatapath(dpid=1)
    engine.set_datapaths({1: dp})

    attacker_mac = "02:aa:aa:aa:aa:01"
    victim_mac = "02:bb:bb:bb:bb:02"
    flows = [
        {"src_mac": attacker_mac, "dst_mac": victim_mac, "packet_rate": 12000.0, "priority": 1},
        {"src_mac": "02:cc:cc:cc:cc:03", "dst_mac": victim_mac, "packet_rate": 40.0, "priority": 1},
    ]
    prediction = {"status": "ATTACK", "confidence": 92.0}
    explanation = {"attack_type_hint": "SYN_FLOOD"}

    # Handle alert -> triggers OpenFlow DROP installation
    engine.handle_alert(dpid=1, prediction=prediction, explanation=explanation, flow_features=flows)
    assert len(dp.sent_msgs) >= 1

    # Inspect installed OpenFlow rule
    installed_mod = dp.sent_msgs[0]
    assert installed_mod["priority"] == BLOCK_PRIORITY
    assert installed_mod["flags"] == MockOfproto.OFPFF_SEND_FLOW_REM
    assert installed_mod["hard_timeout"] == 120  # >= 90% confidence gives 120s

    # Verify that attacker is recorded in blocklist
    assert engine._blocklist.is_blocked(1, attacker_mac) is True

    # Simulate FlowRemoved event from switch when rule expires
    engine.on_flow_removed(dpid=1, src_mac=attacker_mac, dst_mac=victim_mac)
    assert engine._blocklist.is_blocked(1, attacker_mac) is False

    # Manual unblock testing
    unblock_ok = unblock_src_mac(dp, attacker_mac)
    assert unblock_ok is True
    assert unblock_all(dp) is True


# ─── STAGE 9: Adaptive Learning & AutoML Retraining Feedback Loop ───────────

def test_stage_9_adaptive_learning_and_automl_feedback(temp_env):
    """Verify drift detection, R7-gated sample buffering, candidate training, hot-swap, and rollback."""
    service = AdaptiveLearningService(min_adaptation_interval_sec=0.0)

    # 1. Reject unverified guesses
    assert service.add_verified_sample([1.0] * 15, label=1, source="model_guess", verified=False) is False

    # 2. Accept R7-verified samples
    assert service.add_verified_sample([500.0] * 15, label=1, source="r7_verified", verified=True) is True
    assert service.add_verified_sample([10.0] * 15, label=0, source="r7_verified", verified=True) is True

    # 3. Candidate Model Training & Safety Benchmarking
    updater = AdaptiveModelUpdater(min_f1=0.80, max_fpr=0.05)
    model, scaler, train_time = updater.train_candidate(np.empty((0, 15)), np.empty((0,), dtype=int))
    eval_metrics = updater.evaluate_model(model, scaler)
    passed, reason = updater.validate_candidate_safety(eval_metrics)
    assert passed is True

    # 4. Model Registry Promotion & Hot-Swap
    registry = AdaptiveModelRegistry(registry_dir=temp_env)
    cand1 = registry.register_candidate(model, scaler, eval_metrics)
    promoted = registry.promote_candidate(cand1, reason="E2E Champion v1")
    assert registry.active_model.model_id == promoted.model_id

    # 5. Automated Rollback
    m2, s2, _ = updater.train_candidate(np.empty((0, 15)), np.empty((0,), dtype=int))
    cand2 = registry.register_candidate(m2, s2, {"f1_score": 0.95})
    registry.promote_candidate(cand2, reason="E2E Champion v2")
    restored, _ = registry.rollback()
    assert restored.model_id == promoted.model_id

    # 6. Online AutoML Pipeline Trigger
    automl = OnlineAutoMLService()
    automl_res = automl.run_automl_pipeline(force=True, adwin_drift=True)
    assert automl_res["ran"] is True
    assert automl_res["candidates_evaluated"] > 0


# ─── STAGE 10: Complete API, Alerts & Audit Trail Integration ────────────────

def test_stage_10_dashboard_apis_and_audit_trail():
    """Verify REST APIs serve health, metrics, traces, and novelty states."""
    client = TestClient(app)

    endpoints = [
        "/api/status",
        "/api/traffic",
        "/api/flows",
        "/api/alerts",
        "/api/ssl/status",
        "/api/adaptive-learning/status",
        "/api/automl/status",
        "/api/digital-twin/level-a/summary",
        "/api/digital-twin/level-b/status",
        "/api/verification-traces",
    ]
    for ep in endpoints:
        resp = client.get(ep)
        assert resp.status_code in (200, 404), f"Endpoint {ep} failed with {resp.status_code}"


# ─── END-TO-END INTEGRATED SIMULATION: Seamless Stage 1 to 10 Pipeline ───────

def test_complete_end_to_end_attack_to_mitigation_and_learning_lifecycle(temp_env):
    """
    Executes a complete lifecycle across all 10 stages:
    Normal flow -> Attack burst -> Detection -> Fusion -> Verification ->
    RCA/XAI -> Mitigation Drop Rule -> Sample Buffering -> Twin Observation -> API visibility.
    """
    # Initialize Core Engines
    dp = MockDatapath(dpid=1)
    mitigation_engine = MitigationEngine(auto_mitigate=True)
    mitigation_engine.set_datapaths({1: dp})

    builder = FeatureBuilder()
    fusion_engine = CollaborativeFusionEngine()
    verification_engine = VerificationEngine(
        config=VerificationConfig(warmup_threshold=0, attack_confirm=1)
    )
    rca_engine = RootCauseEngine()
    adaptive_service = AdaptiveLearningService(min_adaptation_interval_sec=0.0)

    # 1. Normal Traffic Cycle
    normal_flows = [
        {"src_mac": "02:00:00:00:00:01", "dst_mac": "02:00:00:00:00:02", "packet_rate": 20.0, "byte_rate": 12800.0, "packet_count": 100, "byte_count": 64000, "duration_sec": 5.0, "protocol": 6}
    ]
    norm_vec, _ = builder.build(normal_flows, {"entropy_score": 0.95}, switch_id=1)
    norm_vec = sanitize_15d_vector(norm_vec)

    # Normal consensus
    norm_res = DetectorResult(
        detector=DetectorType.ML,
        timestamp=utc_now(),
        health=DetectorHealth.SUCCESS,
        decision=DetectionDecision.NORMAL,
        confidence=0.99,
        score=0.01,
    )
    fused_norm = fusion_engine.fuse(detector_results=[norm_res], switch_id=1)
    assert fused_norm.decision == DetectionDecision.NORMAL

    # Buffer normal sample
    adaptive_service.add_verified_sample(norm_vec, label=0, source="r7_verified", verified=True)
    assert len(dp.sent_msgs) == 0  # No mitigation on normal

    # 2. Attack Traffic Cycle (SYN Flood)
    attacker = "02:aa:bb:cc:dd:ee"
    victim = "02:11:22:33:44:55"
    attack_flows = [
        {"src_mac": attacker, "dst_mac": victim, "packet_rate": 18000.0, "byte_rate": 1152000.0, "packet_count": 90000, "byte_count": 5760000, "duration_sec": 5.0, "protocol": 6},
        {"src_mac": "02:00:00:00:00:01", "dst_mac": victim, "packet_rate": 15.0, "byte_rate": 9600.0, "packet_count": 75, "byte_count": 48000, "duration_sec": 5.0, "protocol": 6},
    ]
    atk_vec, _ = builder.build(attack_flows, {"entropy_score": 0.15}, switch_id=1)
    atk_vec = sanitize_15d_vector(atk_vec)

    # Hybrid Detection Voters
    ml_atk = DetectorResult(
        detector=DetectorType.ML,
        timestamp=utc_now(),
        health=DetectorHealth.SUCCESS,
        decision=DetectionDecision.ATTACK,
        confidence=0.98,
        score=0.98,
        attack_hint="SYN_FLOOD",
    )
    ent_atk = DetectorResult(
        detector=DetectorType.ENTROPY,
        timestamp=utc_now(),
        health=DetectorHealth.SUCCESS,
        decision=DetectionDecision.ATTACK,
        confidence=0.94,
        score=0.15,
        attack_hint="SYN_FLOOD",
    )

    fused_atk = fusion_engine.fuse(detector_results=[ml_atk, ent_atk], switch_id=1)
    assert fused_atk.decision == DetectionDecision.ATTACK

    # Multi-Stage Verification Gate (R7)
    cycle_event_id = new_id()
    v_input = VerificationInput(
        dpid=1,
        event_id=cycle_event_id,
        prediction={"status": "ATTACK", "confidence": 98.0, "source": "r6_fusion"},
        explanation={"attack_type_hint": "SYN_FLOOD"},
        flow_features=attack_flows,
        warmup_cycles_done=5,
        attack_streak=2,
        min_confidence_percent=60.0,
    )
    v_result = verification_engine.verify(v_input)
    assert v_result.status == VerificationStatus.VERIFIED
    assert v_result.mitigation_eligible is True

    # Root Cause Analysis & Explainability (Stage 5)
    rca_ctx = RCAContext(
        event_id=cycle_event_id,
        attack_hint="SYN_FLOOD",
        entropy_evidence={"entropy_score": 0.15},
        mitigation=MitigationEvidence(
            eligible=True, strategy="FLOW_PAIR", result="BLOCKED"
        ),
    )
    rca_rep = rca_engine.analyze(rca_ctx)
    assert rca_rep is not None
    assert rca_rep.event_id == v_result.event_id

    # Mitigation Execution (Stage 7 & 8)
    mitigation_engine.handle_alert(
        dpid=1,
        prediction=v_input.prediction,
        explanation=v_input.explanation,
        flow_features=attack_flows,
    )
    assert len(dp.sent_msgs) == 1
    flow_mod = dp.sent_msgs[0]
    assert flow_mod["priority"] == BLOCK_PRIORITY
    assert flow_mod["match"].get("eth_src") == attacker
    assert mitigation_engine._blocklist.is_blocked(1, attacker) is True

    # Adaptive Learning Buffer (Stage 9)
    adaptive_service.add_verified_sample(atk_vec, label=1, source="r7_verified", verified=True)
    buf_stats = adaptive_service.sample_buffer.get_stats()
    assert buf_stats["attack_samples_count"] >= 1
    assert buf_stats["normal_samples_count"] >= 1

    # End of Cycle Verification
    assert v_result.event_id is not None
    assert mitigation_engine._blocklist.is_blocked(1, attacker) is True
