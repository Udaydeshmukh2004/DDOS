# IntelliShield SDN — Defect Log & Remediation Report

**Project:** IntelliShield SDN: A Self-Adaptive Hybrid Framework for DDoS Detection in Software-Defined Networks  
**Author:** Senior QA Engineer & Python Test Automation Specialist  
**Report Version:** 1.0.0  
**Scope:** Core Controller Subsystems (Telemetry, Feature Pipeline, AutoML Registry, Mitigation)  

---

## Defect Summary Index

| Defect ID | Module | Severity | Summary | Related Test | Status |
|---|---|---|---|---|---|
| **DEF_01** | `ml_models.ml_utils` | High | `safe_mean()` propagates `NaN`/`Inf` telemetry values into feature space | `TC_01` | CLOSED / VERIFIED |
| **DEF_02** | `ml_models.ml_utils` | High | `validate_vector()` accepts corrupt non-numeric strings and crashes on `None` | `TC_02` | CLOSED / VERIFIED |
| **DEF_03** | `ml_models.feature_builder` | High | `FeatureBuilder.build()` crashes on `None` flow entries in telemetry batch | `TC_03` | CLOSED / VERIFIED |
| **DEF_04** | `adaptive_learning.model_registry` | Critical | `promote_candidate()` unconditionally promotes `REJECTED` / null models | `TC_04` | CLOSED / VERIFIED |
| **DEF_05** | `mitigation.flow_blocker` | Critical | `_is_safe_to_block()` bypasses protected check on uppercase broadcast MACs | `TC_05` | CLOSED / VERIFIED |

---

## Detailed Defect Reports

### DEF_01: Safe Arithmetic Propagates NaN and Inf Values in Telemetry

- **Defect ID:** `DEF_01`
- **Component / File:** [ml_models/ml_utils.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/ml_models/ml_utils.py)
- **Functions:** `safe_mean()`, `safe_max()`, `safe_min()`
- **Severity:** High
- **Linked Regression Test:** [test_tc01_telemetry_nan_inf_handling in tests/test_defect_regression_tc01_tc05.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/tests/test_defect_regression_tc01_tc05.py)

#### 1. Reproduction Steps
1. Execute `safe_mean([float('nan'), 10.0, 30.0])`.
2. Inspect the returned arithmetic value.
3. Observe that the returned value is `nan` instead of `20.0`.
4. Execute `safe_mean([float('nan'), float('inf')])`.
5. Observe that the returned value is `nan` instead of `0.0`.

#### 2. Root Cause Analysis
In `ml_models/ml_utils.py`, `safe_mean` and `safe_max` previously filtered elements using `vals = [v for v in values if v is not None]`. Because Python evaluates `math.isnan(v)` as a non-None float, `NaN` values remained in `vals`. In Python arithmetic, any operation involving `NaN` evaluates to `NaN` (`sum([float('nan'), 10.0]) == nan`). When telemetry counters experience momentary division by zero or incomplete data in `flow_monitor.py`, `NaN` propagated unchecked into the 15-dimensional ML feature vector.

#### 3. Corrective Code Change
Filtered out non-numeric values, booleans, `math.isnan(v)`, and `math.isinf(v)`:
```python
def safe_mean(values: list) -> float:
    """Return arithmetic mean, or 0.0 for empty / all-None/NaN lists."""
    if not values:
        return 0.0
    vals = [
        float(v) for v in values
        if v is not None and not isinstance(v, bool) and isinstance(v, (int, float))
        and not (math.isnan(v) or math.isinf(v))
    ]
    return sum(vals) / len(vals) if vals else 0.0
```

#### 4. Verification Evidence
- **Initial:** `AssertionError: safe_mean returned NaN on input [nan, 10.0, 30.0]` (FAIL)
- **Retest:** `safe_mean([nan, 10.0, 30.0]) == 20.0` and `safe_mean([nan, inf]) == 0.0` (PASS)

---

### DEF_02: Feature Validation Bypassed by String Data and Crashes on Null

- **Defect ID:** `DEF_02`
- **Component / File:** [ml_models/ml_utils.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/ml_models/ml_utils.py)
- **Functions:** `validate_vector()`, `sanitize_vector()`
- **Severity:** High
- **Linked Regression Test:** [test_tc02_feature_validation_rejects_corrupt_types in tests/test_defect_regression_tc01_tc05.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/tests/test_defect_regression_tc01_tc05.py)

#### 1. Reproduction Steps
1. Call `validate_vector(["corrupted_metric"] * 15, 15)`.
2. Observe that the function returns `True`.
3. Call `validate_vector(None, 15)`.
4. Observe an unhandled `TypeError: object of type 'NoneType' has no len()`.

#### 2. Root Cause Analysis
`validate_vector` checked `for v in vector: if v is None or (isinstance(v, float) and (math.isnan(v) or math.isinf(v))): return False`. When string elements were passed, `isinstance(v, float)` evaluated to `False`, so the invalid items passed the check undetected. Furthermore, no guard existed to check whether `vector` was `None` or a valid sequence before calling `len(vector)`.

#### 3. Corrective Code Change
Added sequence validation, strict numeric type enforcement (`isinstance(v, (int, float))` excluding booleans), and robust coercion in `sanitize_vector()`:
```python
def validate_vector(vector: list, expected_len: int) -> bool:
    """Check that a feature vector has the correct length, numeric types, and no NaN/Inf."""
    if vector is None or not hasattr(vector, "__len__"):
        logger.warning("[validate_vector] Non-sequence vector passed: %s", type(vector))
        return False
    if len(vector) != expected_len:
        logger.warning("[validate_vector] Length mismatch: got %d, expected %d",
                       len(vector), expected_len)
        return False
    for v in vector:
        if v is None or isinstance(v, bool) or not isinstance(v, (int, float)):
            logger.warning("[validate_vector] Non-numeric/None item in vector: %r", v)
            return False
        if math.isnan(v) or math.isinf(v):
            logger.warning("[validate_vector] NaN/Inf in vector: %r", v)
            return False
    return True
```

#### 4. Verification Evidence
- **Initial:** `AssertionError: validate_vector incorrectly accepted a list of string values as a valid numeric feature vector` (FAIL)
- **Retest:** Returns `False` on non-numeric vectors and `False` on `None` inputs (PASS)

---

### DEF_03: Feature Builder Pipeline Crashes on Null Flow Entries

- **Defect ID:** `DEF_03`
- **Component / File:** [ml_models/feature_builder.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/ml_models/feature_builder.py)
- **Function:** `FeatureBuilder.build()`
- **Severity:** High
- **Linked Regression Test:** [test_tc03_feature_builder_handles_none_flow_entries in tests/test_defect_regression_tc01_tc05.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/tests/test_defect_regression_tc01_tc05.py)

#### 1. Reproduction Steps
1. Instantiate `builder = FeatureBuilder()`.
2. Pass a flow list containing a `None` entry: `flow_features = [None, {"packet_rate": 50.0, "byte_rate": 5000.0, "duration_sec": 10.0, "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02"}]`.
3. Call `builder.build(flow_features, persist=False)`.
4. Observe the console output and returned vector.
5. Notice that `FeatureBuilder` catches an `AttributeError`, logs a traceback error, and discards all telemetry data from the valid flow, returning an empty `[0.0] * 15` vector.

#### 2. Root Cause Analysis
In `ml_models/feature_builder.py`, list comprehensions `[f.get("packet_rate", 0.0) for f in flow_features]` directly invoked `.get()` on every item in `flow_features`. If an unparsed OpenFlow packet or disconnect injected `None` or a non-dict into `flow_features`, `None.get()` threw `AttributeError`. This forced the entire monitoring cycle into the fallback handler, resetting genuine network traffic statistics to zero.

#### 3. Corrective Code Change
Pre-filtered `flow_features` to isolate valid dictionary structures before evaluating rates, counts, and durations:
```python
# ── Flow-based features ───────────────────────────────────────────
valid_flows = [f for f in (flow_features or []) if isinstance(f, dict)]
pkt_rates  = [f.get("packet_rate", 0.0) for f in valid_flows]
byte_rates = [f.get("byte_rate",   0.0) for f in valid_flows]
durations  = [f.get("duration_sec", 0.0) for f in valid_flows]
src_macs   = {f.get("src_mac", "") for f in valid_flows if f.get("src_mac")}
dst_macs   = {f.get("dst_mac", "") for f in valid_flows if f.get("dst_mac")}
...
flow_count = float(len(valid_flows))
```

#### 4. Verification Evidence
- **Initial:** `AssertionError: Expected packet_rate_mean=50.0, got 0.0 (fell back to dummy vector)` (FAIL)
- **Retest:** `vector[0] == 50.0` and `vector[4] == 1.0` (PASS)

---

### DEF_04: AutoML Model Registry Allows Promotion of Rejected and Null Models

- **Defect ID:** `DEF_04`
- **Component / File:** [adaptive_learning/model_registry.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/adaptive_learning/model_registry.py)
- **Function:** `AdaptiveModelRegistry.promote_candidate()`
- **Severity:** Critical
- **Linked Regression Test:** [test_tc04_registry_promotion_gate_enforcement in tests/test_defect_regression_tc01_tc05.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/tests/test_defect_regression_tc01_tc05.py)

#### 1. Reproduction Steps
1. Create an `AdaptiveModelRegistry` instance and promote a baseline model (`v1.0-active`).
2. Create a candidate model with poor accuracy (`0.40`) and reject it via `registry.reject_candidate(bad_candidate, "Low accuracy")`.
3. Call `registry.promote_candidate(bad_candidate, "Forced promotion")`.
4. Observe that the rejected candidate is accepted, set to `ACTIVE`, and replaces the baseline model.
5. Call `registry.promote_candidate(None, "Null promotion")`.
6. Observe that `self.active_model.status` is set to `ARCHIVED`, leaving the system without an active model when an `AttributeError` terminates execution.

#### 2. Root Cause Analysis
`AdaptiveModelRegistry.promote_candidate()` lacked preconditions. It immediately mutated state (`self.active_model.status = "ARCHIVED"`) before validating `candidate`. Consequently, candidates with status `"REJECTED"` or `None` corrupted the active model registry state.

#### 3. Corrective Code Change
Added strict validation before state transitions:
```python
def promote_candidate(
    self,
    candidate: RegisteredModel,
    reason: str,
) -> RegisteredModel:
    """Promote a candidate model to ACTIVE."""
    if candidate is None:
        raise ValueError("Cannot promote null candidate model")
    if not isinstance(candidate, RegisteredModel):
        raise ValueError(f"Invalid candidate type: {type(candidate)}")
    if candidate.status == "REJECTED":
        raise ValueError(
            f"Cannot promote a REJECTED candidate model ({candidate.version_tag})"
        )

    # Archive current active model as previous model
    if self.active_model is not None:
        self.active_model.status = "ARCHIVED"
        self.previous_model = self.active_model
    ...
```

#### 4. Verification Evidence
- **Initial:** `Failed: DID NOT RAISE ValueError` (FAIL)
- **Retest:** `with pytest.raises(ValueError)` successfully verified, preserving active baseline model (PASS)

---

### DEF_05: Mitigation Safety Guard Bypassed by Uppercase Broadcast MAC

- **Defect ID:** `DEF_05`
- **Component / File:** [mitigation/flow_blocker.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/mitigation/flow_blocker.py)
- **Function:** `_is_safe_to_block()`
- **Severity:** Critical
- **Linked Regression Test:** [test_tc05_mitigation_safety_guard_protected_mac in tests/test_defect_regression_tc01_tc05.py](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/tests/test_defect_regression_tc01_tc05.py)

#### 1. Reproduction Steps
1. Call `_is_safe_to_block("FF:FF:FF:FF:FF:FF")`.
2. Observe that the function returns `True`.
3. Call `_is_safe_to_block("01:80:C2:00:00:0E")`.
4. Observe that the function returns `True`.

#### 2. Root Cause Analysis
In `mitigation/flow_blocker.py`, `PROTECTED_MACS` stores MAC strings in lowercase format (`"ff:ff:ff:ff:ff:ff"`, `"01:80:c2:00:00:0e"`). The lookup condition `if not mac or mac in PROTECTED_MACS:` compared the input string directly without normalizing casing. Because uppercase strings like `"FF:FF:FF:FF:FF:FF"` were not in `PROTECTED_MACS`, the safety check returned `True`. Under automated mitigation, this allowed the OpenFlow controller to install a DROP flowmod for the network broadcast address, cutting off all network ARP/broadcast communication.

#### 3. Corrective Code Change
Normalized MAC strings via `strip().lower()` and added type checking:
```python
def _is_safe_to_block(mac: str) -> bool:
    """
    Safety guard: check a MAC address is safe to block.

    Returns False for broadcast, multicast, or zero MACs.
    """
    if not mac or not isinstance(mac, str):
        return False
    mac_lower = mac.strip().lower()
    if mac_lower in PROTECTED_MACS:
        return False
    # Skip IPv6 multicast range (33:33:xx:xx:xx:xx)
    if mac_lower.startswith("33:33"):
        return False
    return True
```

#### 4. Verification Evidence
- **Initial:** `AssertionError: Safety guard failed: uppercase broadcast MAC FF:FF:FF:FF:FF:FF was marked safe to block! assert True is False` (FAIL)
- **Retest:** `_is_safe_to_block("FF:FF:FF:FF:FF:FF") is False` and `_is_safe_to_block("01:80:C2:00:00:0E") is False` (PASS)

