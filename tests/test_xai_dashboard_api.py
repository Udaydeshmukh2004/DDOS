#!/usr/bin/env python3
"""Unit tests for XAI FastAPI endpoints in dashboard/api.py."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from fastapi.testclient import TestClient
import dashboard.api as api_mod
from ml_models.feature_builder import FEATURE_NAMES
from shared_contracts.models import RootCauseReport, new_id
from rca.persistence import JsonlRCAStore


def _sample_vector(packet_rate_max: float = 80.0) -> list[float]:
    base = {
        "packet_rate_mean": 50.0,
        "packet_rate_max": packet_rate_max,
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
    return [float(base[n]) for n in FEATURE_NAMES]


class TestXAIDashboardApi(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(api_mod.app)
        self._orig_rca = api_mod.RCA_REPORTS_JSONL

    def tearDown(self):
        api_mod.RCA_REPORTS_JSONL = self._orig_rca

    def test_01_get_xai_features(self):
        res = self.client.get("/api/xai/features")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total_features"], 15)
        self.assertEqual(len(data["features"]), 15)
        self.assertIn("descriptions", data)
        self.assertIn("normal_ranges", data)
        self.assertIn("packet_rate_max", data["descriptions"])
        self.assertIn("packet_rate_max", data["normal_ranges"])

    def test_02_post_xai_explain_normal(self):
        vec = _sample_vector(packet_rate_max=80.0)
        res = self.client.post("/api/xai/explain", json={"vector": vec})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("status", data)
        self.assertIn("summary", data)
        self.assertIn("narrative", data)
        self.assertEqual(data["feature_names"], list(FEATURE_NAMES))

    def test_03_post_xai_explain_attack_with_counterfactual(self):
        vec = _sample_vector(packet_rate_max=4500.0)
        res = self.client.post(
            "/api/xai/explain",
            json={
                "vector": vec,
                "prediction": {"status": "ATTACK", "confidence": 99.0},
                "event_id": "test-event-123",
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["prediction_status"], "ATTACK")
        self.assertIn("counterfactual", data)
        if data["counterfactual"] is not None:
            self.assertTrue(data["counterfactual"]["achievable"])
            self.assertGreater(len(data["counterfactual"]["required_changes"]), 0)

    def test_04_post_xai_explain_validation_error(self):
        # Invalid length vector
        res = self.client.post("/api/xai/explain", json={"vector": [1.0, 2.0]})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Expected 15 features", res.json()["detail"])

    def test_05_post_xai_counterfactual(self):
        vec = _sample_vector(packet_rate_max=5000.0)
        res = self.client.post(
            "/api/xai/counterfactual",
            json={"vector": vec, "target_decision": "NORMAL", "max_features": 3},
        )
        self.assertEqual(res.status_code, 200)
        cf = res.json()
        self.assertTrue(cf["achievable"])
        self.assertEqual(cf["target_decision"], "NORMAL")
        self.assertGreater(len(cf["required_changes"]), 0)
        self.assertLessEqual(len(cf["required_changes"]), 3)

    def test_06_get_xai_by_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp) / "root_cause_reports.jsonl"
            api_mod.RCA_REPORTS_JSONL = tmp_path

            event_id = new_id()
            report = RootCauseReport(
                report_id=new_id(),
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
                summary="SYN flood on s1",
                suspected_source="00:00:00:00:00:01",
                affected_target="00:00:00:00:00:02",
                contributing_signals=["ml", "xai"],
                contributing_features={
                    "xai": {
                        "local_path_features": ["packet_rate_max"],
                        "counterfactual_guidance": ["Lower packet_rate_max to <= 1500"],
                    }
                },
                explanation_summary="High packet rate anomaly",
            )
            JsonlRCAStore(tmp_path).append(report)

            # Valid query
            res = self.client.get(f"/api/xai/event/{event_id}")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["event_id"], event_id)
            self.assertEqual(data["explanation_summary"], "High packet rate anomaly")
            self.assertIn("xai", data)
            self.assertIn("counterfactual_guidance", data["xai"])

            # Non-existent query
            res_404 = self.client.get("/api/xai/event/non-existent-id")
            self.assertEqual(res_404.status_code, 404)


if __name__ == "__main__":
    unittest.main()

