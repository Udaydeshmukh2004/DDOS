"""
================================================================================
IntelliShield SDN — Defect-Fix-Validation Regression Suite (TC_01 to TC_05)
================================================================================

File        : tests/test_defect_regression_tc01_tc05.py
Author      : Senior QA Engineer & Python Test Automation Specialist
Description :
    Automated regression test suite targeting five genuine software defects
    identified in the core IntelliShield SDN architecture:
      - TC_01: ml_models.ml_utils — Telemetry validation: safe_mean propagates NaN/Inf
      - TC_02: ml_models.ml_utils — Feature validation: validate_vector permits string data
      - TC_03: ml_models.feature_builder — Telemetry error handling: None entries cause pipeline failure
      - TC_04: adaptive_learning.model_registry — Promotion gate: rejected/null models promoted to ACTIVE
      - TC_05: mitigation.flow_blocker — Mitigation safety: uppercase broadcast MAC bypassed guard
================================================================================
"""

import math
import pytest

from ml_models.ml_utils import safe_mean, safe_max, validate_vector, sanitize_vector
from ml_models.feature_builder import FeatureBuilder
from adaptive_learning.model_registry import AdaptiveModelRegistry, RegisteredModel
from mitigation.flow_blocker import _is_safe_to_block


# ---------------------------------------------------------------------------
# TC_01: Telemetry Validation — Handling NaN and Inf in Safe Arithmetic
# ---------------------------------------------------------------------------
def test_tc01_telemetry_nan_inf_handling():
    """
    TC_01: Verify that safe_mean filters out NaN and Inf values from flow statistics
    rather than propagating NaN into downstream feature computations.
    """
    telemetry_samples = [float("nan"), 10.0, 30.0]
    result = safe_mean(telemetry_samples)
    
    # Expected: NaN is filtered out, arithmetic mean of [10.0, 30.0] is 20.0
    assert not math.isnan(result), f"safe_mean returned NaN on input {telemetry_samples}"
    assert result == 20.0, f"Expected 20.0, got {result}"

    # Also test all-NaN telemetry list defaults safely to 0.0
    all_nan = [float("nan"), float("inf")]
    assert safe_mean(all_nan) == 0.0, f"Expected 0.0 for all-NaN/Inf list, got {safe_mean(all_nan)}"


# ---------------------------------------------------------------------------
# TC_02: Feature Validation — Type and Corrupt String Rejection
# ---------------------------------------------------------------------------
def test_tc02_feature_validation_rejects_corrupt_types():
    """
    TC_02: Verify that validate_vector rejects non-numeric/string vectors
    and handles None inputs safely without raising unhandled TypeError.
    """
    corrupt_vector = ["corrupted_metric"] * 15
    # Expected: Non-numeric strings must fail validation
    assert validate_vector(corrupt_vector, 15) is False, (
        "validate_vector incorrectly accepted a list of string values as a valid numeric feature vector"
    )

    # Expected: None vector must safely return False, not raise TypeError
    assert validate_vector(None, 15) is False, (
        "validate_vector raised an unhandled exception or returned True for None input"
    )


# ---------------------------------------------------------------------------
# TC_03: Feature Builder Data Sanitization — Telemetry with None flow entries
# ---------------------------------------------------------------------------
def test_tc03_feature_builder_handles_none_flow_entries():
    """
    TC_03: Verify that FeatureBuilder.build safely ignores None / malformed entries
    in flow_features instead of crashing with AttributeError and returning a blank dummy vector.
    """
    builder = FeatureBuilder()
    flow_features = [
        None,  # Malformed flow entry (e.g. unparsed OpenFlow packet or disconnect)
        {
            "packet_rate": 50.0,
            "byte_rate": 5000.0,
            "duration_sec": 10.0,
            "src_mac": "00:00:00:00:00:01",
            "dst_mac": "00:00:00:00:00:02",
        },
    ]

    vector, meta = builder.build(flow_features=flow_features, persist=False)
    # Expected: Valid flow entry is retained; packet_rate_mean should be 50.0, flow_count should be 1.0
    assert vector[0] == 50.0, f"Expected packet_rate_mean=50.0, got {vector[0]} (fell back to dummy vector)"
    assert vector[4] == 1.0, f"Expected flow_count=1.0, got {vector[4]}"


# ---------------------------------------------------------------------------
# TC_04: AutoML / Model Registry Promotion Gate — Reject Invalid/Rejected Models
# ---------------------------------------------------------------------------
def test_tc04_registry_promotion_gate_enforcement(tmp_path):
    """
    TC_04: Verify that AdaptiveModelRegistry.promote_candidate rejects candidate models
    with status 'REJECTED' or candidate=None, preventing corruption of the active model.
    """
    registry = AdaptiveModelRegistry(registry_dir=str(tmp_path))

    # Establish a baseline active model
    baseline = registry.register_candidate(
        estimator="estimator_v1", scaler="scaler_v1", metrics={"accuracy": 0.95}
    )
    registry.promote_candidate(baseline, "Baseline initialization")
    assert registry.active_model.version_tag == "v1.0-active"

    # Create a candidate that failed verification gates
    bad_candidate = registry.register_candidate(
        estimator="failing_model",
        scaler="failing_scaler",
        metrics={"accuracy": 0.40},
    )
    registry.reject_candidate(bad_candidate, "Accuracy below acceptable threshold")
    assert bad_candidate.status == "REJECTED"

    # Attempt to promote the rejected candidate: must raise ValueError and preserve active model
    with pytest.raises(ValueError, match="REJECTED|invalid|cannot promote"):
        registry.promote_candidate(bad_candidate, "Unauthorized promotion of rejected candidate")

    # Verify active model was NOT overwritten or corrupted
    assert registry.active_model.version_tag == "v1.0-active"

    # Also test promoting None must raise ValueError and not archive active model
    with pytest.raises(ValueError):
        registry.promote_candidate(None, "Invalid promotion")
    assert registry.active_model.version_tag == "v1.0-active"


# ---------------------------------------------------------------------------
# TC_05: Mitigation Engine Safety Guard — Case-Insensitive Protected MAC Check
# ---------------------------------------------------------------------------
def test_tc05_mitigation_safety_guard_protected_mac():
    """
    TC_05: Verify that _is_safe_to_block prevents blocking broadcast and multicast MACs
    regardless of letter casing (e.g. FF:FF:FF:FF:FF:FF).
    """
    # Uppercase broadcast MAC must NEVER be safe to block
    assert _is_safe_to_block("FF:FF:FF:FF:FF:FF") is False, (
        "Safety guard failed: uppercase broadcast MAC FF:FF:FF:FF:FF:FF was marked safe to block!"
    )

    # Uppercase LLDP multicast MAC must NEVER be safe to block
    assert _is_safe_to_block("01:80:C2:00:00:0E") is False, (
        "Safety guard failed: uppercase LLDP MAC 01:80:C2:00:00:0E was marked safe to block!"
    )

    # Legitimate host MAC should be safe to block
    assert _is_safe_to_block("00:00:00:00:00:05") is True

