"""
Automated Test Execution for 5 Randomly Selected Implemented Scenarios
Verifying real execution failures against actual project modules.
"""

import math
import pytest

from entropy_engine.entropy_utils import bucket_values
from ml_models.attack_type_classifier import classify_attack_type
from online_automl.selector import ChampionSelector
from mitigation.blocklist_manager import BlocklistManager
from mitigation.mitigation_engine import _collapse_flow_pairs


# ---------------------------------------------------------------------------
# Test Case 1: Entropy / Telemetry Discretization on NaN Telemetry
# ---------------------------------------------------------------------------
def test_tc01_entropy_bucket_nan_handling():
    """
    Module: entropy_engine.entropy_utils
    Scenario: Continuous flow telemetry containing NaN is passed to bucket_values.
    Expected: Sanitize or handle NaN values gracefully without raising unhandled ValueError.
    """
    telemetry_samples = [float("nan"), 10.0, 50.0]
    buckets = bucket_values(telemetry_samples, num_buckets=5)
    assert isinstance(buckets, list)
    assert len(buckets) == 3


# ---------------------------------------------------------------------------
# Test Case 2: DDoS Attack Type Classifier on Incomplete Feature Vector
# ---------------------------------------------------------------------------
def test_tc02_attack_classifier_truncated_vector():
    """
    Module: ml_models.attack_type_classifier
    Scenario: High-load monitoring cycle yields a truncated feature vector (5 dims).
    Expected: Fall back safely to 'UNKNOWN_ANOMALY' without crashing with IndexError.
    """
    partial_vector = [10.0, 20.0, 300.0, 400.0, 1.0]
    hint = classify_attack_type(partial_vector)
    assert hint == "UNKNOWN_ANOMALY"


# ---------------------------------------------------------------------------
# Test Case 3: AutoML Champion Selector Metric Scoring with Missing Metrics
# ---------------------------------------------------------------------------
def test_tc03_automl_selector_null_metrics():
    """
    Module: online_automl.selector
    Scenario: AutoML candidate has None metrics during early/failed training epoch.
    Expected: compute_score(None) should return 0.0 or a valid float without AttributeError.
    """
    score = ChampionSelector.compute_score(None)
    assert isinstance(score, float)
    assert score == 0.0


# ---------------------------------------------------------------------------
# Test Case 4: Mitigation Engine Telemetry Pair Collapsing with Null Packet Rate
# ---------------------------------------------------------------------------
def test_tc04_mitigation_collapse_null_packet_rate():
    """
    Module: mitigation.mitigation_engine
    Scenario: Telemetry batch has flow dictionary with 'packet_rate': None.
    Expected: _collapse_flow_pairs defaults packet_rate to 0.0 without unhandled TypeError.
    """
    flow_features = [
        {
            "src_mac": "00:00:00:00:00:01",
            "dst_mac": "00:00:00:00:00:02",
            "packet_rate": None,
        }
    ]
    collapsed = _collapse_flow_pairs(flow_features)
    assert len(collapsed) == 1
    assert collapsed[0]["packet_rate"] == 0.0


# ---------------------------------------------------------------------------
# Test Case 5: Mitigation Blocklist Manager Query with Null MAC
# ---------------------------------------------------------------------------
def test_tc05_mitigation_blocklist_none_mac():
    """
    Module: mitigation.blocklist_manager
    Scenario: Mitigation engine receives an alert with missing/null source MAC address.
    Expected: should_block(dpid, None) returns False safely without raising AttributeError.
    """
    manager = BlocklistManager()
    result = manager.should_block(dpid=1, mac=None)
    assert result is False

