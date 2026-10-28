#!/usr/bin/env python3
"""
Unit tests for Enhanced XAI capabilities (Counterfactuals, Autoencoder Reconstruction, Isolation Forest).
"""

from __future__ import annotations

import os
import sys
import unittest
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ml_models.feature_builder import FEATURE_NAMES
from xai import (
    AttributionScope,
    CounterfactualExplanation,
    CounterfactualStep,
    ExplanationMethod,
    ExplanationStatus,
    XAIEngine,
    compute_counterfactual,
    explain_isolation_forest,
    explain_reconstruction_error,
)
from xai.models import PredictionExplanation


def _synthetic_vector(**overrides):
    base = {
        "packet_rate_mean": 50.0,
        "packet_rate_max": 80.0,
        "byte_rate_mean": 10000.0,
        "byte_rate_max": 20000.0,
        "flow_count": 8.0,
        "duration_mean": 10.0,
        "unique_src_count": 5.0,
        "unique_dst_count": 4.0,
        "src_entropy": 0.85,
        "dst_entropy": 0.80,
        "packet_entropy": 0.75,
        "byte_entropy": 0.75,
        "flow_entropy": 0.80,
        "entropy_score": 0.80,
        "flow_concentration": 0.15,
    }
    base.update(overrides)
    return [float(base[n]) for n in FEATURE_NAMES]


def _train_models():
    rng = np.random.RandomState(42)
    # Generate 50 normal samples around synthetic normal baseline
    normal_base = np.array(_synthetic_vector())
    # Add gentle percentage noise to features
    noise = rng.normal(loc=0.0, scale=0.02, size=(50, len(FEATURE_NAMES)))
    X_normal = normal_base * (1.0 + noise)

    # 50 attack samples with massive packet_rate_max and packet_rate_mean
    X_attack = X_normal.copy()
    X_attack[:, 0] *= 5.0  # packet_rate_mean
    X_attack[:, 1] += rng.normal(loc=3500, scale=100, size=50)  # packet_rate_max

    X = np.vstack([X_normal, X_attack])
    y = np.array([0] * 50 + [1] * 50)

    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)

    dt = DecisionTreeClassifier(max_depth=4, random_state=42)
    dt.fit(Xs, y)

    iso = IsolationForest(n_estimators=10, random_state=42)
    iso.fit(Xs)

    ae = MLPRegressor(hidden_layer_sizes=(16, 8, 16), max_iter=300, random_state=42)
    ae.fit(X_normal, X_normal)  # trained to reconstruct normal

    return dt, iso, ae, scaler


class TestXAIEnhancements(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dt, cls.iso, cls.ae, cls.scaler = _train_models()
        cls.eng = XAIEngine()

    def test_01_tree_counterfactual_generation(self):
        # Attack vector with high packet_rate_mean and packet_rate_max
        vec = _synthetic_vector(packet_rate_mean=300.0, packet_rate_max=4000.0)
        cf = compute_counterfactual(
            vec,
            FEATURE_NAMES,
            decision_tree=self.dt,
            scaler=self.scaler,
            target_decision="NORMAL",
        )
        self.assertTrue(cf.achievable)
        self.assertEqual(cf.target_decision, "NORMAL")
        self.assertGreater(len(cf.required_changes), 0)
        self.assertGreater(len(cf.guidance), 0)

        # Check step properties
        step = cf.required_changes[0]
        self.assertIsInstance(step.feature, str)
        self.assertIsInstance(step.current_value, float)
        self.assertIsInstance(step.target_value, float)
        self.assertIsInstance(step.delta, float)
        self.assertIn(step.operator, ("<=", ">"))
        self.assertIn("change:", step.remediation_action)

    def test_02_heuristic_counterfactual_fallback(self):
        # Vector with values exceeding NORMAL_RANGES
        vec = _synthetic_vector(packet_rate_max=5000.0, flow_count=100.0)
        cf = compute_counterfactual(
            vec,
            FEATURE_NAMES,
            decision_tree=None,
            scaler=None,
            target_decision="NORMAL",
        )
        self.assertTrue(cf.achievable)
        self.assertGreater(len(cf.required_changes), 0)
        self.assertIn("heuristic", cf.summary.lower())

    def test_03_reconstruction_error_explainer(self):
        # Normal vector should have small errors
        vec_norm = _synthetic_vector()
        attrs_n, mse_n, sum_n = explain_reconstruction_error(vec_norm, self.ae, FEATURE_NAMES)
        self.assertIsInstance(mse_n, float)

        # Attack vector should have high reconstruction error on perturbed dimension
        vec_att = _synthetic_vector(packet_rate_max=5000.0)
        attrs_a, mse_a, sum_a = explain_reconstruction_error(vec_att, self.ae, FEATURE_NAMES, top_k=3)
        self.assertGreater(mse_a, mse_n)
        self.assertEqual(len(attrs_a), 3)

        top_attr = attrs_a[0]
        self.assertEqual(top_attr.scope, AttributionScope.RECONSTRUCTION_ERROR.value)
        self.assertIsNotNone(top_attr.importance)
        self.assertIn("%", top_attr.deviation)

    def test_04_isolation_forest_explainer(self):
        vec_att = _synthetic_vector(packet_rate_max=5000.0)
        attrs, summary = explain_isolation_forest(
            vec_att,
            self.iso,
            FEATURE_NAMES,
            scaler=self.scaler,
            top_k=4,
        )
        self.assertEqual(len(attrs), 4)
        self.assertIn("Isolation Forest anomaly", summary)
        top = attrs[0]
        self.assertEqual(top.scope, AttributionScope.ISOLATION_CONTRIBUTION.value)
        self.assertGreater(top.importance, 0.0)

    def test_05_xai_engine_multi_model_explain(self):
        vec = _synthetic_vector(packet_rate_max=3800.0)
        out = self.eng.explain(
            vec,
            {"status": "ATTACK", "confidence": 98.0, "iso_score": 0.85},
            decision_tree=self.dt,
            scaler=self.scaler,
            isolation_forest=self.iso,
            autoencoder=self.ae,
            model_id="multi-model-test",
        )
        self.assertEqual(out.status, ExplanationStatus.OK.value)
        self.assertIsNotNone(out.counterfactual)
        self.assertTrue(out.counterfactual.achievable)
        self.assertGreater(len(out.actionable_guidance), 0)
        self.assertGreater(len(out.isolation_contributions), 0)
        self.assertGreater(len(out.reconstruction_errors), 0)

        # Check narrative contains actionable guidance and model sections
        narrative_upper = out.narrative.upper()
        self.assertIn("ACTIONABLE COUNTERFACTUAL REMEDIATION GUIDANCE", narrative_upper)
        self.assertIn("ISOLATION FOREST", narrative_upper)
        self.assertIn("AUTOENCODER RECONSTRUCTION", narrative_upper)

    def test_06_to_dict_and_content_fingerprint_preservation(self):
        vec = _synthetic_vector(packet_rate_max=3800.0)
        out1 = self.eng.explain(
            vec,
            {"status": "ATTACK", "confidence": 98.0},
            decision_tree=self.dt,
            scaler=self.scaler,
            isolation_forest=self.iso,
            autoencoder=self.ae,
        )
        out2 = self.eng.explain(
            vec,
            {"status": "ATTACK", "confidence": 98.0},
            decision_tree=self.dt,
            scaler=self.scaler,
            isolation_forest=self.iso,
            autoencoder=self.ae,
        )

        d = out1.to_dict()
        self.assertIn("counterfactual", d)
        self.assertIn("reconstruction_errors", d)
        self.assertIn("isolation_contributions", d)
        self.assertIn("actionable_guidance", d)

        # Content fingerprint must be identical across runs
        self.assertEqual(out1.content_fingerprint(), out2.content_fingerprint())


if __name__ == "__main__":
    unittest.main()
