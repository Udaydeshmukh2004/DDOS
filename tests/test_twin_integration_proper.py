"""
Comprehensive automated tests for proper Digital Twin integration in IntelliShield SDN.

Covers:
1. Snapshot creation, schema verification, and network representation
2. Snapshot diffing and delta computation
3. Candidate detection and mitigation policy validation (TP, FP, FN, TN, legitimate traffic impact)
4. Safe feedback workflow (approval gates, export sanitization, read-only isolation)
5. Boundary checking, missing inputs, and path traversal protection
6. FastAPI API endpoints correctness and error handling
7. Forbidden imports and SDN safety isolation
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from dashboard.api import app
from twin.policy_evaluator import (
    DEFAULT_MAX_FPR,
    DEFAULT_MIN_PRECISION,
    DEFAULT_MIN_RECALL,
    FORBIDDEN_IMPORTS as EVALUATOR_FORBIDDEN_IMPORTS,
    evaluate_candidate_policy,
    get_policy_validation,
    read_policy_validations,
)
from twin.snapshot import (
    FORBIDDEN_IMPORTS as SNAPSHOT_FORBIDDEN_IMPORTS,
    capture_snapshot,
    diff_snapshots,
    diff_snapshots_from_paths,
    load_snapshot,
)
from twin.validate import TwinValidationError

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "twin_s2_slim"


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def test_client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def sample_snapshot(tmp_path: Path) -> Dict[str, Any]:
    return capture_snapshot(FIXTURE_DIR, root=tmp_path, persist=True)


@pytest.fixture
def mock_snapshot_a() -> Dict[str, Any]:
    return {
        "schema": "intellishield.twin.snapshot.v1",
        "snapshot_id": "snap-mock-a",
        "created_at": "2026-10-22T10:00:00Z",
        "source_logs_dir": "/mock/logs/run_a",
        "profile_id": "lab_default",
        "profile_fingerprint": "abc123fingerprint",
        "csv_counts": {"flow_stats.csv": 100, "ml_predictions.csv": 50},
        "windows": [
            {
                "scenario_id": "S2",
                "attack_start": "2026-10-22 10:00:20",
                "attack_stop": "2026-10-22 10:00:50",
            }
        ],
        "baseline_vs_attack": {
            "baseline_mean_pkt_s": 120.0,
            "attack_mean_pkt_s": 9500.0,
            "n_baseline_rows": 60,
            "n_attack_rows": 40,
        },
        "system": {"throughput_mean_pkt_s": 5000.0},
        "observation": {"summary": {"n_mitigation_blocks": 2}},
    }


@pytest.fixture
def mock_snapshot_b() -> Dict[str, Any]:
    return {
        "schema": "intellishield.twin.snapshot.v1",
        "snapshot_id": "snap-mock-b",
        "created_at": "2026-10-22T11:00:00Z",
        "source_logs_dir": "/mock/logs/run_b",
        "profile_id": "lab_default",
        "profile_fingerprint": "abc123fingerprint",
        "csv_counts": {"flow_stats.csv": 250, "ml_predictions.csv": 120},
        "windows": [
            {
                "scenario_id": "S2",
                "attack_start": "2026-10-22 11:00:20",
                "attack_stop": "2026-10-22 11:00:50",
            },
            {
                "scenario_id": "S4",
                "attack_start": "2026-10-22 11:01:20",
                "attack_stop": "2026-10-22 11:01:50",
            },
        ],
        "baseline_vs_attack": {
            "baseline_mean_pkt_s": 150.0,
            "attack_mean_pkt_s": 12000.0,
            "n_baseline_rows": 150,
            "n_attack_rows": 100,
        },
        "system": {"throughput_mean_pkt_s": 7500.0},
        "observation": {"summary": {"n_mitigation_blocks": 5}},
    }


# ── 1. Snapshot Creation & Network Representation ────────────────────────────


class TestSnapshotNetworkRepresentation:
    def test_snapshot_contains_topology_and_schema(self, sample_snapshot: Dict[str, Any]):
        assert sample_snapshot["schema"] == "intellishield.twin.snapshot.v1"
        assert "snapshot_id" in sample_snapshot
        assert "created_at" in sample_snapshot
        assert sample_snapshot["control"] == "READ_ONLY"
        assert sample_snapshot["mutates_controller"] is False
        assert sample_snapshot["mutates_mitigation"] is False
        assert sample_snapshot["launches_mininet"] is False

        # Topology model must be present
        topo = sample_snapshot.get("topology")
        assert isinstance(topo, dict)
        assert topo.get("switch_count") == 1
        assert topo.get("host_count") >= 2
        assert len(topo.get("switches", [])) == 1
        assert topo["switches"][0]["switch_id"] == "s1"

        # Check attacker and victim hosts
        hosts = topo.get("hosts", [])
        roles = {h.get("role") for h in hosts}
        assert "attacker" in roles
        assert "victim" in roles

    def test_load_snapshot_from_dir_and_file(self, sample_snapshot: Dict[str, Any]):
        snap_path = Path(sample_snapshot["snapshot_path"])
        loaded_file = load_snapshot(snap_path)
        assert loaded_file is not None
        assert loaded_file["snapshot_id"] == sample_snapshot["snapshot_id"]

        loaded_dir = load_snapshot(snap_path.parent)
        assert loaded_dir is not None
        assert loaded_dir["snapshot_id"] == sample_snapshot["snapshot_id"]

        assert load_snapshot("/non/existent/path") is None


# ── 2. Snapshot Diffing ───────────────────────────────────────────────────────


class TestSnapshotDiffing:
    def test_diff_identical_snapshots(self, mock_snapshot_a: Dict[str, Any]):
        diff = diff_snapshots(mock_snapshot_a, mock_snapshot_a)
        assert diff["schema"] == "intellishield.twin.snapshot_diff.v1"
        assert diff["data_type"] == "RECORDED_DATA"
        assert diff["control"] == "READ_ONLY"
        assert diff["delta"]["flow_rows_delta"] == 0
        assert diff["delta"]["window_count_delta"] == 0
        assert diff["delta"]["baseline_mean_pkt_s_delta"] == 0.0
        assert diff["scenario_comparison"]["identical_scenario_set"] is True
        assert diff["scenario_comparison"]["added_in_compare"] == []
        assert diff["profile_comparison"]["same_fingerprint"] is True

    def test_diff_different_snapshots(
        self, mock_snapshot_a: Dict[str, Any], mock_snapshot_b: Dict[str, Any]
    ):
        diff = diff_snapshots(mock_snapshot_a, mock_snapshot_b)
        assert diff["delta"]["flow_rows_delta"] == 150  # 250 - 100
        assert diff["delta"]["window_count_delta"] == 1  # 2 - 1
        assert diff["delta"]["mitigation_blocks_delta"] == 3  # 5 - 2
        assert diff["delta"]["baseline_mean_pkt_s_delta"] == 30.0  # 150 - 120
        assert diff["delta"]["attack_mean_pkt_s_delta"] == 2500.0  # 12000 - 9500
        assert diff["scenario_comparison"]["added_in_compare"] == ["S4"]
        assert diff["scenario_comparison"]["removed_in_compare"] == []

    def test_diff_snapshots_from_paths(self, tmp_path: Path, mock_snapshot_a: Dict[str, Any], mock_snapshot_b: Dict[str, Any]):
        p_a = tmp_path / "snap_a.json"
        p_b = tmp_path / "snap_b.json"
        p_a.write_text(json.dumps(mock_snapshot_a), encoding="utf-8")
        p_b.write_text(json.dumps(mock_snapshot_b), encoding="utf-8")

        diff = diff_snapshots_from_paths(p_a, p_b)
        assert diff["base"]["snapshot_id"] == "snap-mock-a"
        assert diff["compare"]["snapshot_id"] == "snap-mock-b"

        with pytest.raises(TwinValidationError):
            diff_snapshots_from_paths(tmp_path / "missing_a.json", p_b)

    def test_diff_invalid_inputs(self):
        with pytest.raises(TwinValidationError):
            diff_snapshots("not_a_map", {})  # type: ignore


# ── 3. Candidate Policy Validation & Safe Feedback Workflow ──────────────────


class TestCandidatePolicyValidation:
    def test_candidate_policy_pass_on_safe_threshold(self, mock_snapshot_a: Dict[str, Any]):
        # Baseline is 120 pkt/s, Attack is 9500 pkt/s. Setting threshold at 5000 pkt/s is ideal.
        cand = {
            "policy_name": "Optimal-Threshold-5000",
            "packet_rate_threshold": 5000.0,
            "byte_rate_threshold": 5000000.0,
            "confidence_threshold": 0.75,
            "mitigation_action": "BLOCK",
            "idle_timeout_sec": 30,
        }
        res = evaluate_candidate_policy(mock_snapshot_a, cand, persist=False)
        assert res["schema"] == "intellishield.twin.policy_validation.v1"
        assert res["validation_status"] == "PASS"

        cls = res["classification"]
        assert cls["true_positives"] == 40
        assert cls["false_positives"] == 0
        assert cls["false_negatives"] == 0
        assert cls["true_negatives"] == 60
        assert cls["precision"] == 1.0
        assert cls["recall"] == 1.0
        assert cls["false_positive_rate"] == 0.0

        imp = res["legitimate_traffic_impact"]
        assert imp["impact_rating"] == "NONE"
        assert imp["collateral_damage_pct"] == 0.0
        assert imp["normal_flows_affected"] == 0

        mit = res["mitigation_outcome"]
        assert mit["mitigation_action"] == "BLOCK"
        assert mit["projected_attack_suppression_pct"] == 100.0

        # Safe feedback workflow check
        wf = res["safe_feedback_workflow"]
        assert wf["approval_status"] == "PENDING_OPERATOR_APPROVAL"
        assert wf["can_auto_apply"] is False
        assert wf["controller_export_payload"]["approval_required"] is True

    def test_candidate_policy_fail_on_aggressive_threshold(self, mock_snapshot_a: Dict[str, Any]):
        # Baseline is 120 pkt/s. Setting threshold to 50 pkt/s flags normal traffic (High FP).
        cand = {
            "policy_name": "Overly-Aggressive-50",
            "packet_rate_threshold": 50.0,
            "byte_rate_threshold": 500.0,
            "confidence_threshold": 0.50,
            "mitigation_action": "BLOCK",
            "idle_timeout_sec": 30,
        }
        res = evaluate_candidate_policy(mock_snapshot_a, cand, persist=False)
        assert res["validation_status"] == "FAIL"

        cls = res["classification"]
        assert cls["false_positives"] == 60  # All baseline normal flows flagged!
        assert cls["false_positive_rate"] == 1.0

        imp = res["legitimate_traffic_impact"]
        assert imp["impact_rating"] == "CRITICAL"
        assert imp["collateral_damage_pct"] == 100.0
        assert any("exceeds hard ceiling" in f for f in res["gate_findings"])

    def test_candidate_mitigation_actions(self, mock_snapshot_a: Dict[str, Any]):
        for action in ("BLOCK", "RATE_LIMIT", "OBSERVE"):
            cand = {
                "policy_name": f"Policy-{action}",
                "packet_rate_threshold": 5000.0,
                "byte_rate_threshold": 5000000.0,
                "confidence_threshold": 0.75,
                "mitigation_action": action,
                "idle_timeout_sec": 30,
            }
            res = evaluate_candidate_policy(mock_snapshot_a, cand, persist=False)
            assert res["mitigation_outcome"]["mitigation_action"] == action

    def test_candidate_policy_invalid_bounds(self, mock_snapshot_a: Dict[str, Any]):
        # Negative threshold
        with pytest.raises(TwinValidationError):
            evaluate_candidate_policy(
                mock_snapshot_a, {"packet_rate_threshold": -10.0}, persist=False
            )

        # Invalid confidence
        with pytest.raises(TwinValidationError):
            evaluate_candidate_policy(
                mock_snapshot_a, {"confidence_threshold": 1.5}, persist=False
            )

        # Invalid action
        with pytest.raises(TwinValidationError):
            evaluate_candidate_policy(
                mock_snapshot_a, {"mitigation_action": "INVALID_ACTION"}, persist=False
            )

    def test_candidate_policy_insufficient_evidence(self):
        empty_snap = {
            "snapshot_id": "snap-empty",
            "windows": [],
            "baseline_vs_attack": {},
            "csv_counts": {},
        }
        cand = {"packet_rate_threshold": 5000.0}
        res = evaluate_candidate_policy(empty_snap, cand, persist=False)
        assert res["validation_status"] == "INSUFFICIENT_EVIDENCE"


# ── 4. API Endpoints Correctness ─────────────────────────────────────────────


class TestTwinApiEndpoints:
    def test_api_snapshots_diff_success(self, test_client: TestClient):
        r_snaps = test_client.get("/api/digital-twin/snapshots")
        assert r_snaps.status_code == 200
        snaps = r_snaps.json().get("snapshots", [])
        if len(snaps) >= 2:
            s0 = snaps[0]["snapshot_id"]
            s1 = snaps[1]["snapshot_id"]
            diff_res = test_client.get(
                f"/api/digital-twin/snapshots/diff?base={s0}&compare={s1}"
            )
            assert diff_res.status_code == 200
            data = diff_res.json()
            assert data["schema"] == "intellishield.twin.snapshot_diff.v1"
            assert "delta" in data
            assert "scenario_comparison" in data

    def test_api_snapshots_diff_same_id_error(self, test_client: TestClient):
        res = test_client.get("/api/digital-twin/snapshots/diff?base=snap1&compare=snap1")
        assert res.status_code == 400
        assert "different" in res.json().get("detail", "").lower()

    def test_api_snapshots_diff_path_traversal_blocked(self, test_client: TestClient):
        res = test_client.get(
            "/api/digital-twin/snapshots/diff?base=../../etc/passwd&compare=snap1"
        )
        assert res.status_code == 400

    def test_api_snapshots_diff_not_found(self, test_client: TestClient):
        res = test_client.get(
            "/api/digital-twin/snapshots/diff?base=unknown_1&compare=unknown_2"
        )
        assert res.status_code == 404

    def test_api_policy_validate_success(self, test_client: TestClient):
        cand = {
            "policy_name": "API-Test-Policy",
            "packet_rate_threshold": 5000.0,
            "byte_rate_threshold": 5000000.0,
            "confidence_threshold": 0.80,
            "mitigation_action": "BLOCK",
            "idle_timeout_sec": 30,
            "persist": True,
        }
        res = test_client.post("/api/digital-twin/policies/validate", json=cand)
        assert res.status_code == 200
        data = res.json()
        assert data["schema"] == "intellishield.twin.policy_validation.v1"
        assert "classification" in data
        assert "legitimate_traffic_impact" in data
        assert data["safe_feedback_workflow"]["can_auto_apply"] is False

        # Verify listing
        list_res = test_client.get("/api/digital-twin/policies/validations")
        assert list_res.status_code == 200
        assert list_res.json().get("count", 0) >= 1

        # Verify single lookup
        vid = data["validation_id"]
        single_res = test_client.get(f"/api/digital-twin/policies/validations/{vid}")
        assert single_res.status_code == 200
        assert single_res.json()["validation_id"] == vid

    def test_api_policy_validate_validation_errors(self, test_client: TestClient):
        # Negative rate threshold rejected by Pydantic
        res = test_client.post(
            "/api/digital-twin/policies/validate",
            json={"packet_rate_threshold": -50.0},
        )
        assert res.status_code == 422

        # Invalid action rejected
        res = test_client.post(
            "/api/digital-twin/policies/validate",
            json={"mitigation_action": "INVALID_ACTION"},
        )
        assert res.status_code == 422

    def test_api_policy_validation_path_traversal_blocked(self, test_client: TestClient):
        res = test_client.get(
            "/api/digital-twin/policies/validations/..%2F..%2Fetc%2Fpasswd"
        )
        assert res.status_code in (400, 404)

    def test_api_policy_validation_not_found(self, test_client: TestClient):
        res = test_client.get(
            "/api/digital-twin/policies/validations/twinpol-unknown123"
        )
        assert res.status_code == 404

    def test_api_stats_includes_policy_validations(self, test_client: TestClient):
        res = test_client.get("/api/digital-twin/stats")
        assert res.status_code == 200
        assert "policy_validations" in res.json()


# ── 5. Safety Isolation & Forbidden Imports Check ────────────────────────────


class TestTwinSafetyIsolation:
    def test_evaluator_safety_forbidden_imports(self):
        for mod in EVALUATOR_FORBIDDEN_IMPORTS:
            assert "controller.flow_monitor" in EVALUATOR_FORBIDDEN_IMPORTS
            assert "mitigation.mitigation_engine" in EVALUATOR_FORBIDDEN_IMPORTS
            assert "traffic_generator.traffic_scheduler" in EVALUATOR_FORBIDDEN_IMPORTS

    def test_snapshot_safety_forbidden_imports(self):
        for mod in SNAPSHOT_FORBIDDEN_IMPORTS:
            assert "controller.flow_monitor" in SNAPSHOT_FORBIDDEN_IMPORTS
            assert "mitigation.mitigation_engine" in SNAPSHOT_FORBIDDEN_IMPORTS

    def test_read_only_contracts_preserved(self, mock_snapshot_a: Dict[str, Any]):
        cand = {"packet_rate_threshold": 5000.0}
        res = evaluate_candidate_policy(mock_snapshot_a, cand, persist=False)
        assert res["control"] == "READ_ONLY"
        assert res["mutates_controller"] is False
        assert res["mutates_mitigation"] is False
        assert res["launches_mininet"] is False
