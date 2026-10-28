# IntelliShield SDN — Test Execution Report

**Project:** IntelliShield SDN: A Self-Adaptive Hybrid Framework for DDoS Detection in Software-Defined Networks  
**QA Specialist:** Senior QA Engineer & Python Test Automation Specialist  
**Execution Date:** 2026-10-27  
**Operating System:** Ubuntu 24.04 (WSL2 / Windows 11)  
**Python Runtime:** Python 3.14.4  
**Test Framework:** Pytest 9.1.1, Pluggy 1.7.0, AnyIO 4.15.1, Typeguard 4.4.4  
**Primary Test Suite:** [tests/test_defect_regression_tc01_tc05.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/tests/test_defect_regression_tc01_tc05.py)  
**Evidence Artifacts:**  
- Initial Failure Evidence: [test_evidence/initial_failures.txt](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/test_evidence/initial_failures.txt)  
- Retest Success Evidence: [test_evidence/retest_success.txt](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/test_evidence/retest_success.txt)  

---

## 1. Summary of Execution Metrics

| Metric | Count | Details |
|---|---|---|
| **Genuine Defects Identified** | 5 | All 5 defects identified directly in existing codebase |
| **Initial Failures Reproduced** | 5 | Exactly 5/5 automated test cases failed in initial baseline execution |
| **Code Fixes Applied** | 5 | Targeted, minimal fixes applied across 4 core source files |
| **Post-Fix Retests Passed** | 5 | Exactly 5/5 automated regression tests passed on retest |
| **Neighboring Test Suite Regressions** | 0 | 24/24 neighboring tests passed without error |
| **Environment-Blocked Tests** | 0 | None |
| **Overall Defect Resolution Rate** | 100% | 5 out of 5 defects resolved and verified |

---

## 2. Test Execution Commands & Reproducibility

### 2.1 Initial Defect Capture Command
```bash
PYTHONPATH=. .venv/bin/pytest tests/test_defect_regression_tc01_tc05.py -v --tb=short | tee test_evidence/initial_failures.txt
```

**Result:**
```text
============================= test session starts ==============================
platform linux -- Python 3.14.4, pytest-9.1.1, pluggy-1.7.0 -- .venv/bin/python3
cachedir: .pytest_cache
rootdir: /mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main
collected 5 items

tests/test_defect_regression_tc01_tc05.py::test_tc01_telemetry_nan_inf_handling FAILED [ 20%]
tests/test_defect_regression_tc01_tc05.py::test_tc02_feature_validation_rejects_corrupt_types FAILED [ 40%]
tests/test_defect_regression_tc01_tc05.py::test_tc03_feature_builder_handles_none_flow_entries FAILED [ 60%]
tests/test_defect_regression_tc01_tc05.py::test_tc04_registry_promotion_gate_enforcement FAILED [ 80%]
tests/test_defect_regression_tc01_tc05.py::test_tc05_mitigation_safety_guard_protected_mac FAILED [100%]

============================== 5 failed in 33.25s ==============================
```

---

### 2.2 Post-Fix Retest Verification Command
```bash
PYTHONPATH=. .venv/bin/pytest tests/test_defect_regression_tc01_tc05.py -v --tb=short | tee test_evidence/retest_success.txt
```

**Result:**
```text
============================= test session starts ==============================
platform linux -- Python 3.14.4, pytest-9.1.1, pluggy-1.7.0 -- .venv/bin/python3
cachedir: .pytest_cache
rootdir: /mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main
collected 5 items

tests/test_defect_regression_tc01_tc05.py::test_tc01_telemetry_nan_inf_handling PASSED [ 20%]
tests/test_defect_regression_tc01_tc05.py::test_tc02_feature_validation_rejects_corrupt_types PASSED [ 40%]
tests/test_defect_regression_tc01_tc05.py::test_tc03_feature_builder_handles_none_flow_entries PASSED [ 60%]
tests/test_defect_regression_tc01_tc05.py::test_tc04_registry_promotion_gate_enforcement PASSED [ 80%]
tests/test_defect_regression_tc01_tc05.py::test_tc05_mitigation_safety_guard_protected_mac PASSED [100%]

============================== 5 passed in 26.76s ==============================
```

---

### 2.3 Neighboring Test Regression Verification Command
```bash
PYTHONPATH=. .venv/bin/pytest tests/test_continuous_normal_traffic.py tests/test_adaptive_learning.py tests/test_mitigation_strategy_p04.py -v
```

**Result:**
```text
============================= test session starts ==============================
platform linux -- Python 3.14.4, pytest-9.1.1, pluggy-1.7.0 -- .venv/bin/python3
cachedir: .pytest_cache
rootdir: /mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main
collected 24 items

tests/test_continuous_normal_traffic.py::TestContinuousNormalTrafficConfig::test_scenario_registry_has_continuous_normal PASSED [  4%]
tests/test_continuous_normal_traffic.py::TestContinuousNormalTrafficConfig::test_dashboard_scenarios_has_continuous_normal PASSED [  8%]
tests/test_continuous_normal_traffic.py::TestContinuousNormalTrafficConfig::test_scheduler_cli_supports_continuous_flag PASSED [ 12%]
tests/test_continuous_normal_traffic.py::TestContinuousNormalTrafficConfig::test_control_panel_stop_scenario_method_exists PASSED [ 16%]
tests/test_continuous_normal_traffic.py::TestContinuousNormalTrafficConfig::test_dashboard_api_has_stop_scenario_route PASSED [ 20%]
tests/test_continuous_normal_traffic.py::TestContinuousNormalTrafficConfig::test_run_continuous_normal_script_exists_and_executable PASSED [ 25%]
tests/test_adaptive_learning.py::test_drift_monitor_statistics PASSED    [ 29%]
tests/test_adaptive_learning.py::test_drift_monitor_adwin_alert_recording PASSED [ 33%]
tests/test_adaptive_learning.py::test_sample_buffer_safety_gates PASSED  [ 37%]
tests/test_adaptive_learning.py::test_sample_buffer_bounded_capacity PASSED [ 41%]
tests/test_adaptive_learning.py::test_model_updater_and_safety_checks PASSED [ 45%]
tests/test_adaptive_learning.py::test_model_registry_lifecycle_and_rollback PASSED [ 50%]
tests/test_adaptive_learning.py::test_adaptive_learning_service_end_to_end PASSED [ 54%]
tests/test_mitigation_strategy_p04.py::test_targeted_floods_use_flow_pair PASSED [ 58%]
tests/test_mitigation_strategy_p04.py::test_volumetric_flood_uses_src_mac PASSED [ 62%]
tests/test_mitigation_strategy_p04.py::test_unknown_hint_defaults_to_flow_pair PASSED [ 66%]
tests/test_mitigation_strategy_p04.py::test_missing_victim_mac_uses_src_mac PASSED [ 70%]
tests/test_mitigation_strategy_p04.py::test_low_volume_attack_no_block PASSED [ 75%]
tests/test_mitigation_strategy_p04.py::test_low_confidence_attack_no_block PASSED [ 79%]
tests/test_mitigation_strategy_p04.py::test_high_volume_syn_flood_flow_pair_block PASSED [ 83%]
tests/test_mitigation_strategy_p04.py::test_bidirectional_flood_ignores_victim_reverse_flow PASSED [ 87%]
tests/test_mitigation_strategy_p04.py::test_volumetric_flood_src_mac_block PASSED [ 91%]
tests/test_mitigation_strategy_p04.py::test_hybrid_attack_unknown_anomaly_flow_pair PASSED [ 95%]
tests/test_mitigation_strategy_p04.py::test_block_record_keeps_src_mac_key PASSED [100%]

============================= 24 passed in 27.38s ==============================
```

---

## 3. Test Cases Execution Breakdown

### TC_01: Telemetry Validation — Handling NaN and Inf in Safe Arithmetic
- **Target Module:** `ml_models.ml_utils`
- **Initial Result:** FAIL (`AssertionError: safe_mean returned NaN on input [nan, 10.0, 30.0]`)
- **Fix:** Filtered `math.isnan(v)` and `math.isinf(v)` in `safe_mean()`, `safe_max()`, and `safe_min()`.
- **Retest Result:** PASS (`assert not math.isnan(result)` and `assert result == 20.0`).

### TC_02: Feature Validation — Type and Corrupt String Rejection
- **Target Module:** `ml_models.ml_utils`
- **Initial Result:** FAIL (`AssertionError: validate_vector incorrectly accepted a list of string values as a valid numeric feature vector`)
- **Fix:** Added strict numeric type enforcement (`isinstance(v, (int, float))` and `not isinstance(v, bool)`) and safe sequence guard for `None` inputs in `validate_vector()`. Added resilient coercion fallback in `sanitize_vector()`.
- **Retest Result:** PASS (`validate_vector(['corrupted_metric'] * 15, 15) is False` and `validate_vector(None, 15) is False`).

### TC_03: Feature Builder Data Sanitization — Telemetry with None Flow Entries
- **Target Module:** `ml_models.feature_builder`
- **Initial Result:** FAIL (`AttributeError: 'NoneType' object has no attribute 'get'` triggering generic exception and dummy fallback vector `[0.0]*15`)
- **Fix:** Filtered `valid_flows = [f for f in (flow_features or []) if isinstance(f, dict)]` before extracting rate and duration telemetry.
- **Retest Result:** PASS (`vector[0] == 50.0` and `vector[4] == 1.0`).

### TC_04: AutoML / Model Registry Promotion Gate — Reject Invalid/Rejected Models
- **Target Module:** `adaptive_learning.model_registry`
- **Initial Result:** FAIL (`Failed: DID NOT RAISE ValueError`; rejected model was promoted to `ACTIVE`, replacing known-good model)
- **Fix:** Pre-validated candidate before state mutation: raises `ValueError` if `candidate is None`, invalid type, or `candidate.status == "REJECTED"`.
- **Retest Result:** PASS (`with pytest.raises(ValueError)` successfully caught, active baseline model preserved).

### TC_05: Mitigation Engine Safety Guard — Case-Insensitive Protected MAC Check
- **Target Module:** `mitigation.flow_blocker`
- **Initial Result:** FAIL (`AssertionError: Safety guard failed: uppercase broadcast MAC FF:FF:FF:FF:FF:FF was marked safe to block!`)
- **Fix:** Normalized MAC addresses via `mac.strip().lower()` before querying `PROTECTED_MACS`.
- **Retest Result:** PASS (`_is_safe_to_block("FF:FF:FF:FF:FF:FF") is False`).

