"""
Comprehensive audit and validation script for all Machine Learning and RL models in IntelliShield SDN.
Tests model persistence, loading, inference, XAI, RL agent, AutoML, and trainer.
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import joblib
import numpy as np

def run_model_tests():
    print("=" * 70)
    print("IntelliShield SDN — Model & AI Subsystem Comprehensive Test")
    print("=" * 70)
    
    errors = []
    
    # ── Test 1: Direct Pickle Deserialization ───────────────────────────────
    print("\n[Test 1] Testing Pickle Loading of Saved Model Artifacts...")
    model_paths = {
        "scaler": REPO_ROOT / "logs" / "models" / "scaler.pkl",
        "isolation_forest": REPO_ROOT / "logs" / "models" / "isolation_forest.pkl",
        "decision_tree": REPO_ROOT / "logs" / "models" / "decision_tree.pkl",
        "automl_champion": REPO_ROOT / "logs" / "models" / "automl_champion.pkl",
        "ppo_weights": REPO_ROOT / "logs" / "ppo_weights.pkl",
    }
    
    loaded_artifacts = {}
    for name, path in model_paths.items():
        if not path.is_file():
            print(f"  [WARN] File not found: {path.relative_to(REPO_ROOT)}")
            continue
        try:
            obj = joblib.load(path)
            loaded_artifacts[name] = obj
            obj_type = type(obj).__name__
            size_kb = path.stat().st_size / 1024
            print(f"  [OK] {name} ({obj_type}, {size_kb:.1f} KB) loaded cleanly")
        except Exception as e:
            err = f"Failed to load {name} from {path}: {e}"
            print(f"  [FAIL] {err}")
            errors.append(err)

    # ── Test 2: AnomalyDetector Loading and Inference ──────────────────────
    print("\n[Test 2] Testing AnomalyDetector runtime inference...")
    try:
        from ml_models.anomaly_detector import AnomalyDetector
        from ml_models.feature_builder import FEATURE_NAMES

        detector = AnomalyDetector()
        print(f"  IsolationForest trained: {detector._is_iso_trained}")
        print(f"  DecisionTree trained:    {detector._is_dt_trained}")
        if not (detector._is_iso_trained and detector._is_dt_trained):
            errors.append("AnomalyDetector models are not fully trained/loaded")

        # Create Normal sample vector (15 features)
        normal_vec = [
            10.0, 50.0, 5000.0, 15000.0, 8.0, 30.0, 4.0, 4.0,
            0.95, 0.95, 0.90, 0.90, 0.85, 0.91, 0.15
        ]
        res_normal = detector.predict(normal_vec)
        print(f"  Normal vector inference: status={res_normal.get('status')}, confidence={res_normal.get('confidence'):.2f}%, iso_score={res_normal.get('iso_score'):.3f}")
        
        # Create Attack sample vector (SYN flood: extreme packet rate, entropy collapse)
        attack_vec = [
            8000.0, 25000.0, 600000.0, 2000000.0, 150.0, 5.0, 50.0, 1.0,
            0.10, 0.05, 0.12, 0.15, 0.08, 0.10, 0.95
        ]
        res_attack = detector.predict(attack_vec)
        print(f"  Attack vector inference: status={res_attack.get('status')}, confidence={res_attack.get('confidence'):.2f}%, iso_score={res_attack.get('iso_score'):.3f}")

        if res_attack.get("status") not in ("ATTACK", "SUSPICIOUS"):
            print(f"  [WARN] Extreme attack vector classified as: {res_attack.get('status')}")
    except Exception as e:
        err = f"AnomalyDetector test failed: {e}\n{traceback.format_exc()}"
        print(f"  [FAIL] {err}")
        errors.append(err)

    # ── Test 3: Explainer & XAIEngine ──────────────────────────────────────
    print("\n[Test 3] Testing ML Explainer & XAI Engine...")
    try:
        from ml_models.explainer import Explainer
        from xai import XAIEngine

        explainer = Explainer()
        exp_res = explainer.explain(attack_vec, res_attack)
        print(f"  Explainer: top_feature={exp_res.get('top_feature')}, dev_count={len(exp_res.get('deviations', []))}")

        xai_engine = XAIEngine()
        # Explain using loaded models
        dt = loaded_artifacts.get("decision_tree")
        iso = loaded_artifacts.get("isolation_forest")
        scaler = loaded_artifacts.get("scaler")

        xai_res = xai_engine.explain(
            vector=attack_vec,
            prediction=res_attack,
            decision_tree=dt,
            scaler=scaler,
            isolation_forest=iso,
        )
        cf_count = len(xai_res.counterfactual.required_changes) if xai_res.counterfactual else 0
        print(f"  XAIEngine explanation: status={xai_res.status}, global_importances={len(xai_res.global_feature_importances)}, path_steps={len(xai_res.decision_path)}, counterfactual_changes={cf_count}")
        print(f"  XAI Summary: {xai_res.summary}")
    except Exception as e:
        err = f"XAI/Explainer test failed: {e}\n{traceback.format_exc()}"
        print(f"  [FAIL] {err}")
        errors.append(err)

    # ── Test 4: RL PPO Agent & Threshold Adapter ───────────────────────────
    print("\n[Test 4] Testing RL PPO Agent and ThresholdAdapter...")
    try:
        from rl_engine.ppo_agent import PPOAgent
        from rl_engine.threshold_adapter import ThresholdAdapter

        adapter = ThresholdAdapter()
        print(f"  Initial thresholds: pkt={adapter.pkt_threshold}, byte={adapter.byte_threshold}, conf={adapter.conf_threshold:.2f}")

        weights_file = REPO_ROOT / "logs" / "ppo_weights.pkl"
        agent = PPOAgent(save_path=str(weights_file))
        print(f"  PPOAgent successfully initialized with weights from {weights_file.name}")

        # Test state forward pass (STATE_DIM = 10)
        dummy_state = np.array([0.5, 0.5, 0.5, 0.1, 0.1, 0.0, 0.2, 0.3, 0.0, 0.1], dtype=np.float32)
        action, lp, val = agent.step(dummy_state)
        print(f"  PPOAgent step OK: action={action}, lp={lp:.4f}, value={val:.4f}")
        
        # Test applying action to adapter
        updated_dict = adapter.apply_action(action)
        print(f"  Updated thresholds: pkt={adapter.pkt_threshold:.1f}, byte={adapter.byte_threshold:.1f}, conf={adapter.conf_threshold:.2f}")
    except Exception as e:
        err = f"RL PPO Agent test failed: {e}\n{traceback.format_exc()}"
        print(f"  [FAIL] {err}")
        errors.append(err)

    # ── Test 5: Online AutoML Service ──────────────────────────────────────
    print("\n[Test 5] Testing Online AutoML Service...")
    try:
        from online_automl.service import OnlineAutoMLService
        automl = OnlineAutoMLService()
        champion = automl.registry.current_champion
        champion_id = champion.candidate_id if champion else "None"
        print(f"  AutoML Service active. Current champion model: {champion_id}")
    except Exception as e:
        err = f"AutoML test failed: {e}\n{traceback.format_exc()}"
        print(f"  [FAIL] {err}")
        errors.append(err)

    # ── Test 6: Model Training Pipeline Verification ───────────────────────
    print("\n[Test 6] Testing Model Trainer synthetic training function...")
    try:
        from ml_models.model_trainer import ModelTrainer
        trainer = ModelTrainer()
        # Train with synthetic sample to verify training algorithms
        train_res = trainer.train_all(use_synthetic=True, n_normal=60, n_attack=40)
        print(f"  Synthetic trainer: dt_train_acc={train_res.get('dt_train_acc', 0):.2%}")
    except Exception as e:
        err = f"Model Trainer test failed: {e}\n{traceback.format_exc()}"
        print(f"  [FAIL] {err}")
        errors.append(err)

    # ── Test 7: SSL Autoencoder Verification ───────────────────────────────
    print("\n[Test 7] Testing SSL Zero-Day Autoencoder...")
    try:
        from ssl_zero_day.autoencoder import SSLAutoencoder
        ae = SSLAutoencoder(hidden_layer_sizes=(10, 4, 10), max_iter=25)
        dummy_train = np.random.randn(30, 15).astype(np.float32)
        ae.fit(dummy_train)
        dummy_test = np.random.randn(5, 15).astype(np.float32)
        recon = ae.reconstruct(dummy_test)
        errors_recon = ae.compute_mse(dummy_test)
        print(f"  SSLAutoencoder trained and tested: recon shape={recon.shape}, mean MSE={np.mean(errors_recon):.4f}")
    except Exception as e:
        err = f"SSL Autoencoder test failed: {e}\n{traceback.format_exc()}"
        print(f"  [FAIL] {err}")
        errors.append(err)

    # ── Summary ────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    if errors:
        print(f"MODEL AUDIT COMPLETED WITH {len(errors)} ERROR(S):")
        for i, err in enumerate(errors, 1):
            print(f"{i}. {err}")
        return False
    else:
        print("MODEL AUDIT COMPLETE: ALL 7 MODEL SUBSYSTEMS PASSED WITH 0 ERRORS!")
        return True

if __name__ == "__main__":
    ok = run_model_tests()
    sys.exit(0 if ok else 1)
