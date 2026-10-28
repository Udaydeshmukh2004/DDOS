# Task 16 — Final Reproduction Discrepancy Resolution Report

**Auditor:** Independent Scientific Reproducibility Auditor & Skeptical Reviewer  
**Date:** October 25, 2026  
**Repository:** IntelliShield SDN (`c:\Users\deshm\OneDrive\Desktop\intellishield_sdn-main`)  
**Row-Level Comparison CSV:** [`results/task16_apriori_entropy_row_level_comparison.csv`](file:////mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/results/task16_apriori_entropy_row_level_comparison.csv)  

---

## 1. Executive Scientific Verdict: CONDITIONALLY SUPPORTED WITH FORMAL CORRECTIONS

```
+----------------------------------------------------------------------------------------------------+
|                                    TASK 16 SCIENTIFIC VERDICT:                                     |
|                        CONDITIONALLY SUPPORTED WITH FORMAL CORRECTIONS                             |
+----------------------------------------------------------------------------------------------------+
| 1. A Priori Recall Discrepancy Resolved: The true benchmark recall is 415 / 500 = 83.00%. The value |
|    231 / 500 = 46.20% reported in the Task 15 markdown text was a clerical transcription error in  |
|    the report template; the underlying CSV (task15_reproduced_loato_metrics.csv) correctly had 415.|
| 2. Hybrid Confusion Matrix Grounded: Test set for Seed 42 contains exactly 757 windows (257 benign |
|    + 500 attack). The hybrid produces TP=500, FP=1, TN=256, FN=0. The '1,000 benign / 2 FP' table   |
|    in Task 15 was an ungrounded placeholder copied from a hypothetical 2:1 sampling prompt.         |
| 3. Set Attribution Verified: The 297/18/185 partition applies exactly to the 500 PROBE windows:   |
|    297 (both m2), 17 (DT m2), 1 (DT ovs, Window 1677), 185 (Entropy ovs) -> 500 / 500 (100.0%).   |
| 4. Fold 2 Grouped AUC Explained: Fold 2 contains only 4 test sessions because session               |
|    'OVS_4/2/2020 15:20' has 225 windows, exhausting the 20% fold budget. Zero sessions cross the  |
|    split boundary. LR AUC=0.0000 reflects inverted predictions caused by session-level shift.      |
| 5. Statistical Limitation Disclosed: StratifiedGroupKFold on InSDN is structurally volatile due to  |
|    extreme session size skew (1 to 361 windows). Grouped AUC should not be presented as a single   |
|    unqualified scalar without reporting fold-by-fold variance.                                      |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Item 1: Reconciliation of A Priori Entropy Recall (415 vs 231)

### Forensic Root-Cause Analysis:
The auditor compared `scripts/evaluate_non_rf_loato.py`, `scripts/reproduce_task15_package.py`, and the generated CSV files:

1. **Benchmark Ground Truth:**
   In `data/authentic_insdn_leakage_free.csv`, destination-port entropy is stored in column `packet_entropy`.
   Across all 500 PROBE windows:
   - `metasploitable-2`: **230 windows** have `packet_entropy >= 0.85` (out of 314).
   - `OVS`: **185 windows** have `packet_entropy >= 0.85` (out of 186).
   - Total PROBE windows >= 0.85: **230 + 185 = 415 (83.00%)**.

2. **Executed Code Output in Task 15:**
   Inspection of `results/task15_reproduced_loato_metrics.csv` (Row 1) reveals:
   `PROBE, 42, Entropy_Rule_Based_APriori, Rule-Based Heuristic, TP=415, FP=0, TN=257, FN=85, Total=757, Recall=0.83 (415/500)`.
   The actual executed Python code generated **415 detections (83.00% recall)**.

3. **Origin of the 231 Figure:**
   In `scripts/reproduce_task15_package.py`, the Markdown report generation function contained a hardcoded table template:
   `| **Entropy Rule (A Priori)** | Rule-Based Heuristic | 231 | 0 | 1000 | 269 | 1500 | **46.20%** (231 / 500) |`
   This hardcoded string was copied from an earlier scratch script that evaluated only a partial partition (specifically metasploitable-2 windows where 230-231 windows triggered). The string was never wired to the dynamic output of `calc_metrics()`.

4. **Row-Level Verification:**
   The row-level comparison CSV [`results/task16_apriori_entropy_row_level_comparison.csv`](file:////mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/results/task16_apriori_entropy_row_level_comparison.csv) confirms that every single one of the 500 PROBE windows has identical predictions across Tasks 11, 12, 13, 14, and 15:
   - Exactly 415 rows evaluate to `packet_entropy >= 0.85`.
   - Exactly 85 rows evaluate to `packet_entropy < 0.85`.
   - **Conclusion:** The Task 15 reproduction script executed correctly and produced 415/500, but the Markdown reporting template had a clerical transcription error. The verified metric is **415 / 500 = 83.00%**.

---

## 3. Item 2: Grounding the Test Set Size, Hybrid Confusion Matrix, and Attribution

### A. Test Set Size Grounding: 757 Windows (Not 1,500)
In `data/authentic_insdn_leakage_free.csv`, normal traffic originates entirely from `Normal_data.csv` (N = 1,369 total windows across 76 session groups).

Under the LOATO protocol for PROBE (Seed 42):
- A `GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)` isolates 20% of normal sessions for testing.
- This produces `norm_test` with **257 windows** from 16 sessions.
- In the code: `n_test_norm = min(len(norm_test), n_unseen * 2) = min(257, 1000) = 257`.
- Therefore, the test partition contains:
  - **257 normal windows** (from `Normal_data.csv`)
  - **500 PROBE attack windows** (314 from `metasploitable-2`, 186 from `OVS`)
  - **Total Test Partition Size: N = 757 windows**.

> [!IMPORTANT]
> The table in the Task 15 report showing `1000 TN, 2 FP, Total=1500` was an ungrounded theoretical template based on a hypothetical 2:1 sampling ratio. In reality, only 257 normal windows exist in the disjoint test split.

### B. Recomputed Ground-Truth Confusion Matrices (N = 757):
| Model | TP | FP | TN | FN | Total | Recall (Num / Denom) | Precision (Num / Denom) | FPR (Num / Denom) | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Entropy Rule (A Priori, H >= 0.85)** | 415 | 0 | 257 | 85 | 757 | **83.00%** (415 / 500) | **100.00%** (415 / 415) | **0.00%** (0 / 257) | 0.9071 |
| **Entropy Rule (Val-Tuned, theta = 0.65)**| 482 | 0 | 257 | 18 | 757 | **96.40%** (482 / 500) | **100.00%** (482 / 482) | **0.00%** (0 / 257) | 0.9817 |
| **Decision Tree (Single Tree, depth=4)** | 315 | 1 | 256 | 185 | 757 | **63.00%** (315 / 500) | **99.68%** (315 / 316) | **0.39%** (1 / 257) | 0.7721 |
| **Non-RF Collaborative Hybrid** | **500** | **1** | **256** | **0** | **757** | **100.00%** (500 / 500) | **99.80%** (500 / 501) | **0.39%** (1 / 257) | **0.9990** |

### C. Attribution Verification (297 / 18 / 185):
The attribution applies strictly to the 500 positive PROBE attack windows:
- **Both Triggered (DT and Entropy):** **297 windows** (all on metasploitable-2).
- **DT Only:** **18 windows** (17 on metasploitable-2 + 1 on OVS [Window 1677]).
- **Entropy Only:** **185 windows** (all on OVS).
- **Union:** 297 + 17 + 1 + 185 = **500 / 500 (100.00%)**.
- **False Negatives:** **0 windows (0.00%)**.

---

## 4. Item 3: Deep Audit of Grouped Source-AUC Folds

The auditor conducted a deep forensic investigation into the 5 folds generated by `StratifiedGroupKFold`:

| fold | train_sessions | test_sessions | train_m2_windows | train_ovs_windows | test_m2_windows | test_ovs_windows | dt_auc | lr_auc | Session Overlap |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 104 | 31 | 343 | 752 | 361 | 175 | 0.9971 | 0.9943 | **0** |
| 2 | 131 | 4 | 621 | 702 | 83 | 225 | 0.2470 | 0.0000 | **0** |
| 3 | 101 | 34 | 621 | 751 | 83 | 176 | 0.9900 | 0.9416 | **0** |
| 4 | 101 | 34 | 622 | 751 | 82 | 176 | 0.8707 | 0.8889 | **0** |
| 5 | 103 | 32 | 609 | 752 | 95 | 175 | 0.9971 | 1.0000 | **0** |

### Forensic Explanations:
1. **Why Fold 2 contains only 4 test sessions:**
   Session sizes in InSDN range from 1 to 361 windows (median = 4). One single session (`OVS_4/2/2020 15:20`) contains **225 windows**.
   Because each fold targets approximately 326 windows (20% of 1,631), assigning `OVS_4/2/2020 15:20` to test immediately consumed 69% of Fold 2's budget. To balance the positive class, `StratifiedGroupKFold` added 3 metasploitable-2 sessions (83 windows), reaching 308 windows with just 4 sessions.
2. **Zero Boundary Crossing:**
   Train Sessions and Test Sessions have empty intersection in all 5 folds. Overlap is strictly 0.
3. **Why LR AUC was 0.0000 in Fold 2:**
   Both classes were present (83 metasploitable-2, 225 OVS).
   However, session `OVS_4/2/2020 15:20` was recorded on February 4, 2020, with high-volume traffic that exhibited vastly higher packet rates than the December 2019 OVS sessions.
   The Logistic Regression model (which learned from the other folds that high rate = metasploitable-2) predicted P(metasploitable-2) near 1.0 for the 225 OVS samples and lower probabilities for the 83 metasploitable-2 samples.
   The ranking was **completely inverted**, resulting in a mathematically valid `roc_auc_score` of **0.0000** (1.0 - 0.0000 = 1.0000 if flipped).
4. **Methodological Consequence:**
   The session-grouped AUC cannot be reported as a stable scalar (e.g. 0.8204) without explicitly stating that extreme session size skew causes individual fold AUCs to swing between **0.0000 and 0.9971**.

---

## 5. Master Discrepancy Reconciliation Table

| Metric / Phenomenon | Prior Reports (Tasks 11-14) | Task 15 Report | Ground-Truth Verified Value | Source Script & Data | Root Cause of Discrepancy |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **A Priori Entropy Recall** | 83.00% (415/500) | 46.20% (231/500) | **83.00% (415/500)** | `results/task15_reproduced_loato_metrics.csv` | Hardcoded string in Task 15 Markdown template; actual code produced 415. |
| **Seed 42 Test Normal Count**| 1,000 (assumed) | 1,000 (assumed) | **257 windows** | `authentic_insdn_leakage_free.csv` | 20% test split on 1,369 normal windows yields 257 windows; 1,000 was a theoretical ratio. |
| **Hybrid FP on Test Set** | 2 | 2 | **1 window** | `test_df` (N=757) | On 257 normal test windows, exactly 1 false positive occurs (`Normal_data_5/2/2020 19:19`). |
| **Hybrid TN on Test Set** | 998 | 998 | **256 windows** | `test_df` (N=757) | True negatives out of 257 normal test windows = 257 - 1 = 256. |
| **Hybrid PROBE TP** | 500 | 500 | **500 windows** | `test_df` (N=757) | Verified across all tasks: 100% recall on PROBE test set. |
| **Attribution Partition** | 297 / 18 / 185 | 297 / 18 / 185 | **297 / 18 / 185** | `task15_reproduced_probe_attribution.csv` | Correct and mathematically consistent across all 500 PROBE windows. |
| **Fold 2 Grouped AUC** | Not reported | 0.2470 (DT) / 0.0000 (LR) | **0.2470 (DT) / 0.0000 (LR)** | `results/task15_grouped_source_auc_folds.csv` | Inverted ranking on session `OVS_4/2/2020 15:20` due to session-level rate shift. |

---

## 6. Verification of Computational Reproducibility

The auditor executed `scripts/reproduce_task15_package.py` and audited before/after states:
1. **Source Generation:** All metrics are regenerated directly from `data/authentic_insdn_leakage_free.csv` (SHA256: `30b49f285bd0d39c00dad9d93c5029b6fd4529c7c7993ec65956d8ab41207fc7`).
2. **Computational vs Independent Replication:**
   - **Computational Reproduction:** Confirmed **100% reproducible** on the local Python 3.14 / scikit-learn 1.9 environment using random seeds `[42, 101, 777, 999, 2026]`.
   - **Independent Scientific Replication:** Not yet established. Results are specific to the InSDN dataset and have not been validated on external, independently collected SDN traffic.

---

## 7. Final Scientific Verdict

### **CONDITIONALLY SUPPORTED WITH FORMAL CORRECTIONS**

All material numerical and structural discrepancies have been traced to their exact data rows and code lines. The manuscript must use the verified ground-truth values (**415/500 = 83.00%** a priori entropy recall; **N=757** Seed 42 test set with **TP=500, FP=1, TN=256, FN=0**; and fold-by-fold source-AUC reporting).
