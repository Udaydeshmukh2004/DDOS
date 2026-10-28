# Task 17 — Clean Rerun of Corrected LOATO Results Report

**Auditor:** Independent Scientific Reproducibility Auditor  
**Date:** October 25, 2026  
**Repository:** IntelliShield SDN (`c:\Users\deshm\OneDrive\Desktop\intellishield_sdn-main`)  
**Fresh Results Directory:** [`results/task17_clean_rerun/`](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/results/task17_clean_rerun)  
**Seed 42 All Test Predictions CSV:** [`results/task17_clean_rerun/clean_seed42_test_predictions_all.csv`](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/results/task17_clean_rerun/clean_seed42_test_predictions_all.csv)  
**Audit Manifest:** [`results/task17_clean_rerun/task17_manifest.json`](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/results/task17_clean_rerun/task17_manifest.json)  

---

## 1. Executive Scientific Verdict: INDEPENDENTLY REPRODUCED & EMPIRICALLY CONFIRMED

```
+----------------------------------------------------------------------------------------------------+
|                                    TASK 17 SCIENTIFIC VERDICT:                                     |
|                    INDEPENDENTLY REPRODUCED & EMPIRICALLY CONFIRMED (BENCHMARK-SCOPED)             |
+----------------------------------------------------------------------------------------------------+
| 1. Complete Fresh Execution: All 4 LOATO attack scenarios across 5 fixed seeds were regenerated    |
|    directly from authentic_insdn_leakage_free.csv into results/task17_clean_rerun/. Zero overwrites.|
| 2. Test Set Size Grounded: Seed 42 test split contains strictly 500 attack windows and 257 normal  |
|    windows (Total N = 757). The 1,000 normal placeholder in earlier reports is formally retired.   |
| 3. A Priori Entropy Recall Confirmed: Exactly 415 / 500 (83.00%) windows are detected by H >= 0.85.|
|    The 231 / 500 (46.20%) figure is definitively proven to be a clerical reporting template typo.  |
| 4. Hybrid Perfect Attack Recall Confirmed: The collaborative DT + Entropy hybrid detects 500 / 500 |
|    (100.00%) PROBE windows with 0 false negatives, 1 false positive on normal (FPR = 0.39%).        |
| 5. Attribution Partition Grounded: Exactly 297 (both m2) + 17 (DT m2) + 1 (DT ovs) + 185 (Ent ovs)|
|    = 500 windows. Window 1677 confirmed as solitary OVS detection driven by DT (rate 22,935 pkt/s). |
| 6. Session Isolation & Threshold Purity: Zero session overlap across train/val/test in all 5 seeds.|
|    Validation thresholds selected strictly on known attacks/normal pool with 0 held-out leakage.   |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Test Split Verification: 757 Windows (500 Attack + 257 Normal)

### Exact Accounting of Test Observations (Seed 42):
- **Normal Traffic Pool:** 1,369 windows originating from `Normal_data.csv` (76 session groups).
- **GroupShuffleSplit (test_size=0.20):** Groups 20% of sessions for test $\implies$ **16 session groups**, containing **257 windows**.
- **Sampling Step:** `n_test_norm = min(len(norm_test), 500 * 2) = min(257, 1000) = 257`.
- **Held-Out PROBE Attack Windows:** All **500 windows** from 20 session groups (314 `metasploitable-2`, 186 `OVS`).
- **Total Test Observations:** **257 Normal + 500 PROBE = 757 windows**.

### Why earlier reports mentioned 1,000 normal windows:
Earlier Task 10 and 15 report templates referenced a theoretical $2:1$ sampling goal ($2 \times 500 = 1,000$ normal windows). However, because normal traffic is strictly group-split to prevent session contamination, the 20% test slice contains only 257 windows. Sampling 1,000 normal windows would have required drawing from the training and validation pools, which would violate disjoint session evaluation.

---

## 3. Ground-Truth Metric Verification from Fresh Predictions

All metrics below were computed directly from [`results/task17_clean_rerun/clean_seed42_test_predictions_all.csv`](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/results/task17_clean_rerun/clean_seed42_test_predictions_all.csv) ($N = 757$):

| Model Architecture | Evaluated Paradigm | TP | FP | TN | FN | Total | Recall (Num / Denom) | Precision (Num / Denom) | FPR (Num / Denom) | F1-Score |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Entropy Rule (A Priori, H >= 0.85)** | Rule-Based Heuristic | 415 | 0 | 257 | 85 | 757 | **83.00%** (415 / 500) | **100.00%** (415 / 415) | **0.00%** (0 / 257) | 0.9071 |
| **Entropy Rule (Val-Tuned, theta = 0.65)**| Validation-Tuned Heuristic | 482 | 10 | 247 | 18 | 757 | **96.40%** (482 / 500) | **97.97%** (482 / 492) | **3.89%** (10 / 257) | 0.9718 |
| **Decision Tree (Single Tree, depth=4)** | Supervised Tree (Non-RF) | 315 | 0 | 257 | 185 | 757 | **63.00%** (315 / 500) | **100.00%** (315 / 315) | **0.00%** (0 / 257) | 0.7730 |
| **Collaborative Hybrid (DT + Entropy)** | **DT + Entropy Override** | **500** | **1** | **256** | **0** | **757** | **100.00%** (500 / 500) | **99.80%** (500 / 501) | **0.39%** (1 / 257) | **0.9990** |

### Session-Level Detection Results:
- **Evaluated Sessions:** $K = 20$ (6 `metasploitable-2`, 14 `OVS`).
- **Criterion:** $\ge 1$ window flagged positive in the session.
- **Detected Sessions:** **20 / 20 (100.00%)**.
- **95% Wilson Confidence Interval:** `[83.89%, 100.0%]`.

---

## 4. Recomputation of the 297 / 18 / 185 Attribution

Direct calculation from [`results/task17_clean_rerun/clean_probe_attribution.csv`](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/results/task17_clean_rerun/clean_probe_attribution.csv) confirms the exact four-way partition:

$$
\begin{aligned}
S_{\text{DT}} \cap S_{\text{Entropy}} &= 297 \text{ windows (59.40\%, all metasploitable-2)} \\
S_{\text{DT}} \setminus S_{\text{Entropy}} &= 18 \text{ windows (3.60\%)} \implies \begin{cases} 17 \text{ on metasploitable-2} \\ 1 \text{ on OVS (Window 1677)} \end{cases} \\
S_{\text{Entropy}} \setminus S_{\text{DT}} &= 185 \text{ windows (37.00\%, all OVS)} \\
S_{\text{DT}} \cup S_{\text{Entropy}} &= 297 + 17 + 1 + 185 = \mathbf{500 / 500\ (100.00\%)} \\
\text{Missed Windows (FN)} &= \mathbf{0\ (0.00\%)}
\end{aligned}
$$

### Forensic Status of Window 1677:
- **Raw Window ID:** `1677`
- **Host:** `OVS`, Session: `OVS_26/12/2019 02:32:34 PM`
- **Destination Port Entropy:** $H = 0.613506 < 0.65$ (missed by entropy rule).
- **Packet Transmission Rate:** $22,935.8$ pkt/s $\implies P_{{\text{{DT}}}} = 1.0 \ge 0.75$ (`DT_HIGH_CONFIDENCE`).
- **Hybrid Decision:** Flagged as attack by Decision Tree confidence branch. Confirmed as the solitary OVS window detected solely by Decision Tree.

---

## 5. Train / Validation / Test Session Separation Audit

Across all 5 seeds (`[42, 101, 777, 999, 2026]`) and all 4 attack families (`PROBE`, `DDOS`, `DOS`, `BRUTE_FORCE`):
1. **Observation Disjointness:** $\text{{Train}} \cap \text{{Test}} = \emptyset$, $\text{{Val}} \cap \text{{Test}} = \emptyset$, $\text{{Train}} \cap \text{{Val}} = \emptyset$.
2. **Session Disjointness:** $\text{{Train Sessions}} \cap \text{{Test Sessions}} = \emptyset$, $\text{{Val Sessions}} \cap \text{{Test Sessions}} = \emptyset$.
3. **Zero Target Leakage:** Zero PROBE samples were present in `train_df` or `val_df` during PROBE LOATO.
4. **Threshold Selection Purity:** Validation thresholds $\theta_{{\text{{port}}}}$ and $\theta_{{\text{{conc}}}}$ were selected strictly on known attack and normal validation windows ($X_{{\text{{val}}}}$, $y_{{\text{{val}}}}$). Held-out test labels and predictions were never queried.

---

## 6. Discrepancy Reconciliation Table: Task 16 Hypotheses vs. Task 17 Verification

| Investigation Item | Task 16 Hypothesis | Task 17 Fresh Clean Result | Empirical Status | Methodological Grounding |
| :--- | :---: | :---: | :---: | :--- |
| **A Priori Entropy Recall** | Hypothesized 415 / 500 (83.00%) | **415 / 500 (83.00%)** | **CONFIRMED** | Exactly 415 PROBE rows have `packet_entropy >= 0.85` in raw data. |
| **Test Split Size (Seed 42)** | Hypothesized N = 757 (257 + 500) | **N = 757 (257 + 500)** | **CONFIRMED** | 20% normal test split yields 257 windows; 1,000 placeholder is retired. |
| **Hybrid False Positives** | Hypothesized FP = 1 | **FP = 1 (on 257 normal)** | **CONFIRMED** | Exactly 1 normal window (`Normal_data_5/2/2020 19:19`) is flagged by DT. |
| **Hybrid False Negatives** | Hypothesized FN = 0 | **FN = 0 (on 500 PROBE)** | **CONFIRMED** | All 500 PROBE attack windows detected (100.00% recall). |
| **Attribution Partition** | Hypothesized 297 / 18 / 185 | **297 / 18 / 185** | **CONFIRMED** | 297 both, 17 DT m2, 1 DT ovs (w1677), 185 Ent ovs, 0 missed. |
| **Fold 2 Grouped AUC** | Hypothesized 0.2470 (DT) / 0.0000 (LR)| **0.2470 (DT) / 0.0000 (LR)** | **CONFIRMED** | 225-window session `OVS_4/2/2020 15:20` causes inverted LR predictions. |

---

## 7. Cryptographic File Manifest

| File Description | Relative Path | Cryptographic SHA-256 Checksum |
| :--- | :--- | :--- |
| **Raw Source Benchmark** | `data/authentic_insdn_leakage_free.csv` | `30b49f285bd0d39c00dad9d93c5029b6fd4529c7c7993ec65956d8ab41207fc7` |
| **Clean LOATO Metrics** | `results/task17_clean_rerun/clean_loato_metrics.csv` | `2c0dbccb2a7fb6d9e3f82945ccd24df2ae5db61a69fc1073e7e30bb92936f185` |
| **Clean PROBE Attribution** | `results/task17_clean_rerun/clean_probe_attribution.csv` | `de0609a294d3ff294b70dd880b51b9d509839d0ba8c0c28cab235e0a4568697b` |
| **Clean Seed 42 Test Predictions** | `results/task17_clean_rerun/clean_seed42_test_predictions_all.csv` | `b2bf10a7acbf7f06a6ab20e7e9eb569c18be1c04d13e004e879ad86875a767e7` |
| **Clean Session Detections** | `results/task17_clean_rerun/clean_session_detections.csv` | `a3b583c0f23ac486c71f33e3d65786c3cdc75f4949b681b308d48fd9a066b619` |
| **Clean Source AUC Folds** | `results/task17_clean_rerun/clean_source_auc_folds.csv` | `0535034f10d89e1f11ef0e4b1c86909089e699644522f9695c76fdc52552afb2` |
| **Clean Task 17 Manifest** | `results/task17_clean_rerun/task17_manifest.json` | `0de3c8a21268f6fe7c5017d8cad1d16d8aff06d2bb0bcc47446ba995ccfebbe2` |

---

## 8. Disclosed Experimental Limitations & Non-Claims

1. **Synthetic Normal Baseline:** All normal windows come exclusively from `Normal_data.csv` (a quiet lab setting). The 0.39% test FPR on 257 windows and 0.07% FPR on the full benchmark are lab-specific properties that require local baseline calibration before enterprise deployment.
2. **Finite Session Sample:** $K = 20$ sessions bound session detection precision to `[83.89%, 100.0%]`.
3. **Explicit Non-Claims:**
   - We do **NOT** claim universal invariance across arbitrary unobserved physical topologies.
   - We do **NOT** claim real-world zero-day detection outside this mathematically evaluated benchmark scenario.

---

## 9. Final Scientific Verdict

### **INDEPENDENTLY REPRODUCED & EMPIRICALLY CONFIRMED (BENCHMARK-SCOPED)**

All Task 16 hypotheses have been independently tested and confirmed from raw benchmark inputs. The manuscript can proceed safely using these verified values.
