# Task 8 — Scientific Inconsistency Resolution Report

**Auditor:** Skeptical IEEE Transactions Reviewer & Independent Experimental Auditor  
**Date:** October 25, 2026  
**Repository:** IntelliShield SDN (`c:\Users\deshm\OneDrive\Desktop\intellishield_sdn-main`)  
**Audit Report File:** [`reports/TASK_8_SCIENTIFIC_INCONSISTENCY_RESOLUTION.md`](file:////mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/reports/TASK_8_SCIENTIFIC_INCONSISTENCY_RESOLUTION.md)  
**Reproducible Script:** [`scripts/resolve_scientific_inconsistencies.py`](file:////mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/scripts/resolve_scientific_inconsistencies.py)  
**Bidirectional Probe Metrics CSV:** [`results/task8_bidirectional_probe_metrics.csv`](file:////mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/results/task8_bidirectional_probe_metrics.csv)  

---

## 1. Executive Verdict: READY FOR MANUSCRIPT UPDATE WITH EXPLICIT LIMITATIONS

All identified mathematical, methodological, and reporting inconsistencies from Task 7 have been rigorously audited and resolved directly from the code and empirical data:

```
+----------------------------------------------------------------------------------------------------+
|                                    FINAL SCIENTIFIC VERDICT:                                       |
|                       READY FOR MANUSCRIPT UPDATE WITH EXPLICIT LIMITATIONS                        |
+----------------------------------------------------------------------------------------------------+
| 1. The erroneous mathematical claim of "at least 27 distinct ports" for H_port >= 0.85 is formally |
|    withdrawn and replaced with the exact mathematical lower bound: >= 20 distinct ports.           |
| 2. The bidirectional PROBE results are reproduced under both fixed (N=209) and 1:1 balanced        |
|    normal test sets. Mixed generalization is documented honestly: entropy dominates on stealthy    |
|    low-rate scans (99.5% vs 45.7%), while Random Forest retains an advantage on high-rate scans    |
|    with lower port dispersion (87.9% vs 73.3%).                                                    |
| 3. Entropy threshold provenance is separated into an a priori pre-specified heuristic (tau=0.85)   |
|    and a validation-tuned empirical threshold (tau ~ 0.7438, validation FPR = 0.62%).              |
| 4. Effective sample size tables are explicitly labeled as sensitivity scenarios, and empirical     |
|    one-way ANOVA ICC estimates are reported (ICC = 0.76 - 0.99 for attack features).               |
| 5. All 3,776 saved predictions are reconciled to exact per-seed test window counts.                |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Mathematical Proof & Correction of the Port Entropy Threshold

### 2.1 Formula Lineage
In [`scripts/build_empirical_network_features.py`](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/scripts/build_empirical_network_features.py), destination port entropy is calculated as:
$$H_{port}(W) = \frac{-\sum_{i=1}^{k} p_i \log_2(p_i)}{\log_2(\min(|W|, 32))}$$
For tumbling flow windows of $|W| = 50$ flows:
$$\text{denom} = \log_2(\min(50, 32)) = \log_2(32) = 5.0$$
To trigger the threshold $H_{port} \ge 0.85$, the raw Shannon entropy must satisfy:
$$h_{raw} = -\sum_{i=1}^{k} p_i \log_2(p_i) \ge 0.85 \times 5.0 = 4.25$$

### 2.2 Mathematical Lower Bound on Distinct Ports
1. **Continuous Upper Bound:** The maximum entropy for $k$ distinct categories is $\log_2(k)$. Thus:
   $$\log_2(k) \ge 4.25 \implies k \ge 2^{4.25} = 16 \times 2^{0.25} \approx 19.027$$
   Because $k$ must be an integer, continuous uniform probabilities require $k \ge 20$ categories (for $k=19$, $\log_2(19)/5 = 0.84959 < 0.85$).
2. **Discrete Integer Partitions of 50 Flows:**
   - For $k=19$, the most uniform integer partition ($12 \times 3 + 7 \times 2 = 50$) yields $H = 0.84454 < 0.85$.
   - For $k=20$, the most uniform integer partition ($10 \times 3 + 10 \times 2 = 50$) yields $H = 0.85858 \ge 0.85$.

### 2.3 Formal Correction:
> [!IMPORTANT]
> **Correction of Claim:**
> The earlier statement that $H_{port} \ge 0.85$ requires "at least 27 distinct ports" resulted from an erroneous linear scaling of the 32-category ceiling ($32 \times 0.85 = 27.2$). 
> Because Shannon entropy is logarithmic, **the exact mathematical lower bound is 20 distinct destination ports**. No flow distribution of 50 flows with 19 or fewer distinct ports can ever achieve $H_{port} \ge 0.85$.
> Furthermore, $0.85$ is not a "theoretically derived" constant, but an **a priori pre-specified heuristic threshold** corresponding to dispersion across $\ge 20$ distinct destination ports.

---

## 3. Bidirectional PROBE Reproduction & Nuanced Generalization

PROBE attacks in InSDN exist across two distinct virtual testbeds:
- `metasploitable-2`: Nmap horizontal port sweeps with high packet rate (mean $42,583$ pkt/s), $N=314$ windows across 6 session groups.
- `OVS`: Mixed service scans with low packet rate (mean $706$ pkt/s), $N=186$ windows across 14 session groups.

### Exact Experimental Results (Locked Normal Test $N=209$):

| Direction | Model | TP | FP | TN | FN | Attack Recall | Precision | FPR | Accuracy |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **meta-2 $\implies$ OVS** | Decision Tree | 0 | 0 | 209 | 186 | **0.00%** | 0.00% | 0.00% | 52.91% |
| *(Train high-rate,* | Random Forest | 85 | 0 | 209 | 101 | **45.70%** | 100.00% | 0.00% | 74.43% |
| *Test low-rate)* | Port Entropy (A Priori $\tau=0.85$) | 185 | 0 | 209 | 1 | **99.46%** | 100.00% | 0.00% | 99.75% |
| | Port Entropy (Val-Tuned $\tau=0.74$) | 185 | 0 | 209 | 1 | **99.46%** | 100.00% | 0.00% | 99.75% |
| | **Hybrid with Override ($\tau=0.85$)** | **185** | **0** | **209** | **1** | **99.46%** | **100.00%** | **0.00%** | **99.75%** |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **OVS $\implies$ meta-2** | Decision Tree | 215 | 0 | 209 | 99 | **68.47%** | 100.00% | 0.00% | 81.07% |
| *(Train low-rate,* | Random Forest | 276 | 0 | 209 | 38 | **87.90%** | 100.00% | 0.00% | 92.73% |
| *Test high-rate)* | Port Entropy (A Priori $\tau=0.85$) | 230 | 0 | 209 | 84 | **73.25%** | 100.00% | 0.00% | 83.94% |
| | Port Entropy (Val-Tuned $\tau=0.74$) | 235 | 0 | 209 | 79 | **74.84%** | 100.00% | 0.00% | 84.89% |
| | **Hybrid with Override ($\tau=0.85$)** | **235** | **0** | **209** | **79** | **74.84%** | **100.00%** | **0.00%** | **84.89%** |

### Why Benign Counts Differed in Task 7:
- In Task 7, Direction A evaluated on 186 normal windows because the script enforced a 1:1 ratio ($N_{att}=186, N_{norm}=186$). Direction B evaluated on all 209 available normal windows ($N_{att}=314, N_{norm}=209$).
- In Table 3 above, we standardized both directions on the **exact same 209 normal test windows**. The positive detections ($TP$ and Recall) remain identical.

### Objective Scientific Conclusion on Generalization:
- **No universal superiority exists.**
- **Direction A:** When testing on low-rate stealthy port scans, supervised models trained on high-rate traffic fail ($0.0\% - 45.7\%$ recall), while destination port entropy achieves **99.46% recall**.
- **Direction B:** When testing on high-rate traffic containing windows with lower port dispersion, Random Forest achieves **87.90% recall** by leveraging volumetric rate splits, while port entropy achieves **73.25% - 74.84% recall**.
- **Reconciliation with Primary LOATO 100% Recall:** In the primary LOATO evaluation (where all 500 PROBE windows are evaluated together), Random Forest detects the high-rate metasploitable-2 windows, while the entropy override catches the low-rate OVS windows, producing a combined **100.00% recall**.

---

## 4. Provenance of Entropy Thresholds

1. **A Priori Structural Override ($\tau = 0.85$):**
   - Code location: `scripts/evaluate_loato_leakage_free.py` (line 204), `scripts/audit_loato_leakage_free.py` (line 345).
   - Provenance: Pre-specified heuristic chosen prior to test evaluation to capture widespread port contact ($\ge 20$ ports). Zero data used for tuning.
2. **Validation-Tuned Override ($\tau \approx 0.7438$):**
   - Code location: `scripts/resolve_experimental_validity.py` (line 440).
   - Provenance: 99th percentile of normal port entropy in the training-validation split (`np.percentile(val_ports[y_val == 0], 99.0)`).
   - Validation set used: 162 disjoint normal validation windows.
   - Resulting validation FPR: **0.62%** (1 false positive in 162 normal validation windows), safely within the $\le 1.0\%$ budget. Zero test observations were ever accessed.

---

## 5. Effective Sample Size & Intraclass Correlation Coefficient (ICC)

### 5.1 Sensitivity Scenario Table (Kish's Design Effect)
$$D_{eff} = 1 + (\bar{m} - 1)\rho, \quad N_{eff} = N / D_{eff}$$

| Attack Class | Windows ($N$) | Sessions ($K$) | $\bar{m}$ | $N_{eff} (\rho=0.2)$ | $N_{eff} (\rho=0.5)$ | $N_{eff} (\rho=0.8)$ | $N_{eff} (\rho=1.0)$ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **NORMAL** | 1,369 | 373 | 3.67 | 892.4 | 586.3 | 436.5 | **373.0** |
| **DDOS** | 600 | 4 | 150.00 | 19.5 | 7.9 | 5.0 | **4.0** |
| **DOS** | 500 | 99 | 5.05 | 276.2 | 165.3 | 117.9 | **99.0** |
| **PROBE** | 500 | 20 | 25.00 | 86.2 | 38.5 | 24.8 | **20.0** |
| **BRUTE_FORCE** | 28 | 9 | 3.11 | 19.7 | 13.6 | 10.4 | **9.0** |
| **BOTNET** | 3 | 3 | 1.00 | 3.0 | 3.0 | 3.0 | **3.0** |

### 5.2 Empirical One-Way ANOVA ICC Estimates on InSDN Features:
To establish whether high correlation is present, we computed one-way ANOVA ICC(1) across session groups:
- `packet_rate_mean`: DDOS ICC = **0.9991**, DOS ICC = **0.8412**, PROBE ICC = **0.9965**.
- `packet_entropy`: DDOS ICC = **0.8920**, DOS ICC = **0.7845**, PROBE ICC = **0.7634**.
- `flow_concentration`: DDOS ICC = **0.9850**, DOS ICC = **0.8120**, PROBE ICC = **0.8841**.
- **Implication:** Because empirical ICC on attack features exceeds $0.76 - 0.99$, within-session autocorrelation is extreme. For DDoS, the true degrees of freedom are approximately $K = 4$ sessions. The manuscript must not claim that window-level metrics prove generalization across diverse real-world sessions.

---

## 6. Reconciliation of 3,776 Saved Predictions

All 3,776 rows in [`results/task6_per_observation_predictions.csv`](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/results/task6_per_observation_predictions.csv) were audited:
- 5 seeds $\times$ 500 PROBE attack windows = **2,500 positive test observations**.
- Disjoint Normal test windows: Seed 42 ($N=257$), Seed 101 ($N=293$), Seed 777 ($N=260$), Seed 999 ($N=210$), Seed 2026 ($N=256$) = **1,276 negative test observations**.
- Total = $2,500 + 1,276 =$ **3,776 observations**.
- Every reported metric (Recall, Precision, FPR, Accuracy) recomputed from these rows matches [`results/independent_metric_recomputation.csv`](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/results/independent_metric_recomputation.csv) to 4 decimal places.
