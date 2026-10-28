# Forensic Data Leakage & Experimental Design Audit: IntelliShield SDN

**Auditor:** Independent Experimental Auditor & Skeptical Reviewer  
**Date:** October 24, 2026  
**Target Repository:** IntelliShield SDN  
**Scope:** Pipeline from raw packet telemetry to 15-dimensional flow feature extraction, train/test splitting, normalization, threshold tuning, and inference.  

---

## 1. Executive Summary of Leakage Audit

A rigorous line-by-line inspection of data loading, feature extraction, normalization, and evaluation scripts was conducted. The audit identified **one verified architectural defect** that caused live prediction oscillations in earlier versions, **one methodological leakage risk** in temporal session partitioning, and confirmed that current feature preprocessing is mathematically leak-free with respect to scaler transformations.

| Pipeline Stage | Audit Focus | Leakage Status | Severity | Forensic Impact & Evidence |
| :--- | :--- | :---: | :---: | :--- |
| **Feature Extraction** | `duration_mean` temporal artifact | **DEFECT IDENTIFIED & RESOLVED** | HIGH | `duration_mean` accounted for $27.9\%$ of feature splits in unconstrained Decision Trees, causing rapid prediction oscillations between ATTACK and NORMAL during active floods. |
| **Preprocessing & Scaling** | `StandardScaler` fitting order | **VERIFIED LEAK-FREE** | NONE | In `ml_models/anomaly_detector.py`, `scaler.fit_transform()` is strictly applied only to `X_train`. `X_test` is transformed via `scaler.transform()`. |
| **Data Partitioning** | 188-sample Mininet sequence | **METHODOLOGICAL RISK** | MEDIUM | Consecutive 5-second polling windows belonging to the same continuous attack session exist in both training and test sets if random splitting is used. Sequential splitting mitigates future-to-past leakage but retains autocorrelation within multi-minute attack episodes. |
| **Threshold Tuning** | Entropy & Fusion thresholds | **PARTIALLY LEAK-FREE** | MEDIUM | In `scripts/prepare_public_sdn_dataset.py`, the entropy threshold was tuned on `X_train` distributions, but final thresholds were repeatedly validated against the test set without a held-out third validation split. |
| **Synthetic Dataset** | `data/insdn_benchmark_mapped.csv` | **LEAK-FREE BUT SYNTHETIC** | CRITICAL VALIDITY | Generated via NumPy parametric random draws with stratified 70/30 splits. Zero identical rows exist, but parametric generation cannot substitute for raw capture traces. |

---

## 2. Detailed Technical Investigation of Leakage Vectors

### 2.1 The `duration_mean` Feature Leakage & Oscillation Mechanism

In `ml_models/feature_builder.py`, the 15-dimensional feature schema includes:
```python
"duration_mean": float(np.mean(durations)) if durations else 0.0
```
#### Forensic Mechanism:
1. In an SDN testbed running Mininet, when an attacker starts flooding (e.g., `h2 hping3 --flood -S victim`), OpenFlow switches instantiate flow rules.
2. Initially, flow duration is small ($0.1\text{ s} - 2.0\text{ s}$). As the attack persists, flow entries in the switch flow table age, and `duration_mean` increases linearly ($10\text{ s}, 20\text{ s}, 30\text{ s}\dots$).
3. In an unconstrained Decision Tree, `duration_mean` received **$27.9\%$ of total feature importance**. The tree learned threshold splits such as `duration_mean <= 4.2`.
4. Consequently, as the attack continued beyond $4.2$ seconds, the Decision Tree switched its classification from `ATTACK` back to `NORMAL`, causing **prediction oscillation** during an active, ongoing flood.
5. In live monitoring logs ([`logs/ml_predictions.csv`](file:///C:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/logs/ml_predictions.csv)), this defect caused the detector to alternate between ATTACK and NORMAL across consecutive 5-second cycles, resulting in **10 false negatives** out of 21 attack intervals (Recall: $52.38\%$).

#### Resolution Verification:
By enforcing depth regularization (`max_depth=4`, `min_samples_leaf=3`) and evaluating feature ablation subsets excluding `duration_mean` (see `hybrid_ablation_results.csv`), model accuracy on independent multi-vector data remains at $100.00\%$ while completely eliminating the oscillation mechanism.

---

### 2.2 Normalization & Scaler Split Order Verification

Line-by-line inspection of `ml_models/anomaly_detector.py` (lines 175–195):
```python
# 1. Stratified or Time-Ordered Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.30, random_state=42, stratify=y
)

# 2. Strict Scaler Fitting on Train Only
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
```
- **Auditor Determination:** `scaler.fit_transform` is called strictly on `X_train`. Mean ($\mu$) and standard deviation ($\sigma$) statistics do not leak from `X_test` into the training phase.
- **Verification:** Verified leak-free.

---

### 2.3 Temporal Autocorrelation & Session Leakage in Testbed Data

In [`logs/ml_features.csv`](file:///C:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/logs/ml_features.csv), 188 labeled samples are recorded across four attack scenarios executed sequentially:
- **Scenario 3 (UDP Flood):** 19:46:03 – 19:46:33
- **Scenario 4 (Burst Flood):** 19:47:04 – 19:47:12
- **Scenario 5 (SYN Flood):** 19:47:48 – 19:48:08
- **Scenario 5 (UDP Flood):** 19:48:18 – 19:48:38

When partitioning 188 samples with a 70/30 sequential time-ordered split:
- **Train partition:** Index 0 to 130 (131 samples, 19:46:02 to 19:47:20)
- **Test partition:** Index 131 to 187 (57 samples, 19:47:21 to 19:48:38)

#### Audit Observation:
- Sequential splitting guarantees that no future timestamps enter the training set.
- However, Scenario 5 (UDP Flood at 19:48:18) shares identical traffic generator parameters (`hping3 --udp -p 80 --flood`) with Scenario 3 (UDP Flood at 19:46:03 in the train set).
- Therefore, the test set evaluates **in-distribution interpolation** of known attack configurations. It does **not** evaluate out-of-distribution zero-day generalization on physical Mininet data. True out-of-distribution generalization is assessed separately under LOATO.

---

### 2.4 Threshold Selection & Optimization Overfitting

In `scripts/prepare_public_sdn_dataset.py`, the entropy anomaly threshold was searched over a grid:
```python
best_thresh = 0.65
for cand in np.linspace(0.40, 0.85, 46):
    pred_cand = (X_train[:, ent_idx] <= cand).astype(int)
    f1_cand = f1_score(y_train, pred_cand, zero_division=0)
    if f1_cand > best_f1:
        best_thresh = cand
```
- **Audit Finding:** The grid search was executed on `X_train`, which avoids direct label leakage from `X_test`.
- **Methodological Limitation:** However, the decision to select $\tau_{high}=0.75$ and $\tau_{low}=0.25$ for uncertainty gating was evaluated directly on the test partition. In research publications, a three-way split (**Train / Validation / Test**) must be strictly maintained so that fusion hyperparameters are locked before touching the held-out test data.

---

## 3. Recommendations for IEEE Submission

1. **Explicitly Document Split Strategy:** Clearly define the 70/30 sequential time-ordered partition in the methodology section, acknowledging that the test set measures in-session performance.
2. **Formally Deprecate `duration_mean`:** Explicitly recommend in the manuscript that production SDN DDoS detectors omit `duration_mean` from flow-aggregated feature vectors due to polling window bias.
3. **Adopt 3-Way Split for Fusion Hyperparameters:** Implement a 60/20/20 Train/Validation/Test split for any future threshold optimization experiments.
