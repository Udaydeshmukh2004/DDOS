# IntelliShield SDN — Software Test Case & Verification Document
**Project:** IntelliShield SDN: A Self-Adaptive Hybrid Framework for DDoS Detection in Software-Defined Networks  
**Author:** Senior QA Engineer & Python Test Automation Specialist  
**Execution Environment:** Ubuntu (WSL2), Python 3.14.4, pytest 9.1.1  
**Artifact Link:** [tests/test_defect_regression_tc01_tc05.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/tests/test_defect_regression_tc01_tc05.py)  

---

## 1. Executive Summary

This document establishes the formal defect-fix-validation verification report for the IntelliShield SDN controller architecture. Exactly five genuine, reproducible software defects were identified across different functional modules (telemetry statistics calculation, feature vector validation, feature engineering pipeline resilience, AutoML model promotion gates, and OpenFlow automated mitigation safety).

Each defect was captured with an automated regression test in [tests/test_defect_regression_tc01_tc05.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/tests/test_defect_regression_tc01_tc05.py). During the initial execution phase, all five test cases failed identically against the baseline codebase. Minimal, surgical code corrections were then applied, and the identical test cases were re-executed. All five test cases achieved **100% PASS** on retest with zero regressions across neighboring test suites (24/24 passed).

---

## 2. Test Execution History

### 2.1 Initial Execution (Baseline Unpatched Codebase)

The initial test run was conducted against the unpatched codebase. All five test cases demonstrated reproducible failures caused by real functional and architectural defects.

| Test Case | Module | Test Scenario | Expected Result | Actual Result | Status | Note |
|---|---|---|---|---|---|---|
| TC_01 | `ml_models.ml_utils` | `test_tc01_telemetry_nan_inf_handling` | `safe_mean` ignores `NaN`/`Inf` and computes mean of valid numbers (`20.0`), or `0.0` for all-`NaN`. | `safe_mean([nan, 10.0, 30.0])` returned `nan` (`AssertionError`). | FAIL | Malformed telemetry with NaN propagates into downstream 15-D feature vectors. |
| TC_02 | `ml_models.ml_utils` | `test_tc02_feature_validation_rejects_corrupt_types` | `validate_vector` rejects corrupt non-numeric string items and handles `None` input safely returning `False`. | `validate_vector(['corrupted_metric']*15, 15)` returned `True` (`AssertionError`). | FAIL | Type validation bypassed because string is not `float`, allowing strings to reach estimator. |
| TC_03 | `ml_models.feature_builder` | `test_tc03_feature_builder_handles_none_flow_entries` | `FeatureBuilder.build()` skips `None`/malformed flow dicts and retains valid flows (`packet_rate_mean=50.0`, `flow_count=1.0`). | Crashed with `AttributeError: 'NoneType' object has no attribute 'get'`, returned fallback dummy vector (`0.0 == 50.0`). | FAIL | Malformed flow entry in telemetry triggers unhandled exception and drops valid telemetry. |
| TC_04 | `adaptive_learning.model_registry` | `test_tc04_registry_promotion_gate_enforcement` | `promote_candidate` raises `ValueError` when candidate has status `REJECTED` or is `None`, preserving active model. | Did not raise `ValueError`; promoted rejected candidate to `ACTIVE` and overwrote active model. | FAIL | Defective promotion gate allows sub-threshold and rejected models into production. |
| TC_05 | `mitigation.flow_blocker` | `test_tc05_mitigation_safety_guard_protected_mac` | `_is_safe_to_block("FF:FF:FF:FF:FF:FF")` returns `False` to prevent blocking network broadcast traffic. | Returned `True` (`AssertionError: True is False`), allowing broadcast DROP flowmod installation. | FAIL | Case-sensitive lookup in `PROTECTED_MACS` misses uppercase hex MAC addresses. |

---

### 2.2 Post-Fix Retest Execution (Corrected Implementation)

Following the implementation of targeted bug fixes in each respective module, the exact same automated regression tests were re-executed without altering test assertions or expected results.

| Test Case | Module | Test Scenario | Expected Result | Actual Result | Status | Note |
|---|---|---|---|---|---|---|
| TC_01 | `ml_models.ml_utils` | `test_tc01_telemetry_nan_inf_handling` | `safe_mean` ignores `NaN`/`Inf` and computes mean of valid numbers (`20.0`), or `0.0` for all-`NaN`. | Returned `20.0` for mixed telemetry and `0.0` for all-`NaN`/`Inf` list (`assert not math.isnan(result)` PASSED). | PASS | Defect resolved: NaN/Inf and non-numeric values filtered before arithmetic sum. |
| TC_02 | `ml_models.ml_utils` | `test_tc02_feature_validation_rejects_corrupt_types` | `validate_vector` rejects corrupt non-numeric string items and handles `None` input safely returning `False`. | Returned `False` for non-numeric vector and `False` for `None` input without exception. | PASS | Defect resolved: Numeric type check (`isinstance(v, (int, float))`) and sequence guard added. |
| TC_03 | `ml_models.feature_builder` | `test_tc03_feature_builder_handles_none_flow_entries` | `FeatureBuilder.build()` skips `None`/malformed flow dicts and retains valid flows (`packet_rate_mean=50.0`, `flow_count=1.0`). | Skipped `None` entry; returned `packet_rate_mean=50.0` and `flow_count=1.0`. | PASS | Defect resolved: `valid_flows` filter safely extracts valid flow dictionaries. |
| TC_04 | `adaptive_learning.model_registry` | `test_tc04_registry_promotion_gate_enforcement` | `promote_candidate` raises `ValueError` when candidate has status `REJECTED` or is `None`, preserving active model. | Raised `ValueError: Cannot promote a REJECTED candidate model`; active model intact. | PASS | Defect resolved: Upfront candidate validation and active state protection enforced. |
| TC_05 | `mitigation.flow_blocker` | `test_tc05_mitigation_safety_guard_protected_mac` | `_is_safe_to_block("FF:FF:FF:FF:FF:FF")` returns `False` to prevent blocking network broadcast traffic. | Returned `False` for uppercase broadcast/multicast MACs; returned `True` for host MAC. | PASS | Defect resolved: MAC normalized via `mac.strip().lower()` before lookup in `PROTECTED_MACS`. |

---

## 3. Consolidated Defect-Fix Summary Matrix

| Test Case | Module | Target Function | Initial Status | Retest Status | Resolution Verification |
|---|---|---|---|---|---|
| **TC_01** | `ml_models.ml_utils` | `safe_mean()`, `safe_max()` | **FAIL** | **PASS** | Validated arithmetic ignores NaN/Inf |
| **TC_02** | `ml_models.ml_utils` | `validate_vector()`, `sanitize_vector()` | **FAIL** | **PASS** | Enforced numeric typing & sequence bounds |
| **TC_03** | `ml_models.feature_builder` | `FeatureBuilder.build()` | **FAIL** | **PASS** | Flow telemetry filtered for dictionary type |
| **TC_04** | `adaptive_learning.model_registry` | `AdaptiveModelRegistry.promote_candidate()` | **FAIL** | **PASS** | Gated promotion rejects REJECTED/null models |
| **TC_05** | `mitigation.flow_blocker` | `_is_safe_to_block()` | **FAIL** | **PASS** | Case-normalized MAC address security guard |

