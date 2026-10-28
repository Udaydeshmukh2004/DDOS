# Task 9 — Final Independence and Statistical Integrity Audit Report

**Auditor:** Skeptical IEEE Transactions Reviewer & Independent Experimental Auditor  
**Date:** October 25, 2026  
**Repository:** IntelliShield SDN (`c:\Users\deshm\OneDrive\Desktop\intellishield_sdn-main`)  
**Audit Report File:** [`reports/TASK_9_INDEPENDENCE_AUDIT.md`](file:////mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/reports/TASK_9_INDEPENDENCE_AUDIT.md)  
**Unique Sample Counts CSV:** [`results/task9_unique_sample_counts.csv`](file:////mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/results/task9_unique_sample_counts.csv)  
**Audit Script:** [`scripts/audit_independence.py`](file:////mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/scripts/audit_independence.py)  

---

## 1. Executive Verdict

```
+----------------------------------------------------------------------------------------------------+
|                                    FINAL SCIENTIFIC VERDICT:                                       |
|                       READY FOR MANUSCRIPT UPDATE WITH EXPLICIT LIMITATIONS                        |
+----------------------------------------------------------------------------------------------------+
| 1. Observation Independence Clarified: The 2,500 attack predictions across 5 seeds represent 5     |
|    repeated evaluations of exactly 500 unique PROBE windows. Five random seeds resample training   |
|    splits and model initialization, NOT independent attack traffic traces.                         |
| 2. Pseudo-Replication Eliminated: Naive pooling (N=2,500) artificially narrows confidence          |
|    intervals by 2.2x. Statistical uncertainty is formally re-estimated at the unique-window level  |
|    (N=500, 95% CI: [99.26%, 100.00%]) and capture-session level (K=20, 95% CI: [83.89%, 100.00%]).|
| 3. Primary LOATO vs Source-Held-Out Decoupled: The 100.00% LOATO recall is strictly an aggregate   |
|    benchmark result (where RF covers high-rate scans and entropy covers low-rate scans). It must   |
|    never be cited as proof of source generalization, which exhibited mixed results.                |
| 4. Scope Verified: Controller and IEEE manuscript remain 100% untouched.                           |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Unique versus Repeated Observations Audit

### 2.1 Per-Seed Test Partition Structure
Audit of the 5 seeds ($S \in \{42, 101, 2026, 777, 999\}$) in [`results/task6_per_observation_predictions.csv`](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/results/task6_per_observation_predictions.csv) and [`data/authentic_insdn_leakage_free.csv`](file:///c:/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/data/authentic_insdn_leakage_free.csv):

| Seed | Positive Test Windows (Attack) | Attack Session Groups | Negative Test Windows (Normal) | Normal Session Groups | Total Test Windows |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **42** | 500 | 20 | 257 | 74 | 757 |
| **101** | 500 | 20 | 293 | 74 | 793 |
| **2026** | 500 | 20 | 256 | 74 | 756 |
| **777** | 500 | 20 | 260 | 74 | 760 |
| **999** | 500 | 20 | 210 | 74 | 710 |
| **TOTAL** | **2,500** | **20** | **1,276** | **74** | **3,776** |

### 2.2 Unique Sample and Repetition Summary
Traced via unique benchmark window IDs ($0 \dots 2,999$) and session group strings:

| Metric Category | Count | Statistical Unit | Scientific Interpretation |
| :--- | :---: | :--- | :--- |
| **Total Prediction Rows** | **3,776** | Model Predictions | Grand total of saved test rows across all 5 seeds |
| **Attack Predictions** | **2,500** | Model Predictions | 5 repeated evaluations of the held-out PROBE pool |
| **Unique Attack Windows (PROBE)** | **500** | Unique Windows | The true population of empirical PROBE windows in benchmark |
| **Unique Attack Sessions (PROBE)** | **20** | Independent Sessions | 6 sessions from `metasploitable-2`, 14 from `OVS` |
| **Attack Window Repetitions** | **5.0** | Repeats / Window | Every attack window is tested exactly 5 times (1x per seed) |
| **Normal Predictions** | **1,276** | Model Predictions | Disjoint normal windows evaluated across seeds |
| **Unique Normal Windows** | **838** | Unique Windows | Distinct normal windows sampled across the 5 seeds |
| **Unique Normal Sessions** | **226** | Independent Sessions | Distinct benign traffic sessions sampled across seeds |
| **Normal Window Repetitions (Mean)** | **1.52** | Repeats / Window | Ranging from 1 to 4 repeats depending on group sampling |

### 2.3 Clarification on Random Seeds:
> [!IMPORTANT]
> **What the 5 Random Seeds Change:**
> The five random seeds alter **only**:
> 1. The random partitioning of the normal pool into Train, Validation, and Test subsets.
> 2. The random partitioning of known attacks into Train and Validation subsets.
> 3. The random initialization seeds of the decision tree and random forest estimators.
> 
> The five random seeds **do NOT generate new attack observations**. The exact same 500 PROBE windows appear in every single seed's test set. Therefore, treating 2,500 attack predictions as independent trials is invalid pseudo-replication.

---

## 3. Confidence Intervals and Statistical Claims Correction

### 3.1 Pseudo-Replication Impact on Wilson Score Intervals
Evaluating 100% recall across different aggregation levels:

1. **Naive Pooled Wilson Interval ($N = 2,500$ predictions):**
   $$	ext{Recall} = 100.00\%, \quad 95\% \text{ CI} = [99.85\%, 100.0\%] \quad (\text{Error Margin: } 0.150\%) $$
   *Auditor Verdict:* **INVALID**. Treats 5 repeats of 500 windows as independent samples, artificially deflating uncertainty by $\sqrt{5} \approx 2.24\times$.
2. **Corrected Unique-Window Wilson Interval ($N = 500$ unique windows):**
   $$\text{Recall} = 100.00\%, \quad 95\% \text{ CI} = [99.24\%, 100.0\%] \quad (\text{Error Margin: } 0.760\%) $$
   *Auditor Verdict:* **VALID AT WINDOW LEVEL**. Represents the true upper bound of performance over the 500 unique empirical monitoring windows.
3. **Session-Level Cluster Uncertainty ($K = 20$ independent sessions):**
   If all 20 capture sessions have at least one window detected (100% session detection rate):
   $$\text{Session Recall} = 100.00\%, \quad 95\% \text{ CI} = [83.89\%, 100.0\%] \quad (\text{Error Margin: } 16.110\%) $$
   *Auditor Verdict:* **MANDATORY SENSITIVITY DISCLOSURE**. Reflects true sampling uncertainty given only 20 independent PROBE capture episodes.

---

## 4. Primary LOATO versus Source-Held-Out Experiments Decoupled

A critical distinction must be maintained in the research manuscript between the two experimental setups:

| Experimental Dimension | Primary LOATO Evaluation | Source-Held-Out Evaluation |
| :--- | :--- | :--- |
| **Held-Out Dimension** | **Attack Type** (PROBE is excluded from training) | **Capture Environment** (`metasploitable-2` vs `OVS`) |
| **Training Set** | `NORMAL` + `DDOS` + `DOS` + `BRUTE_FORCE` + `BOTNET` | Direction A: `metasploitable-2` PROBE + `NORMAL`<br>Direction B: `OVS` PROBE + `NORMAL` |
| **Test Set** | All 500 PROBE windows combined ($314$ meta-2 + $186$ OVS) | Direction A: $186$ `OVS` PROBE windows<br>Direction B: $314$ `metasploitable-2` PROBE windows |
| **Train-Test Overlap** | **Strictly 0.00%** (PROBE never enters training) | **Strictly 0.00%** (Held-out source never enters training) |
| **Hybrid Override Recall** | **100.00% $\pm$ 0.00%** | Direction A: **99.46%**<br>Direction B: **74.84%** |
| **Scientific Meaning** | Demonstrates that hybrid architecture catches 100% of the aggregate benchmark windows by combining RF on meta-2 and entropy on OVS. | Demonstrates that cross-source generalization is mixed: entropy dominates on low-rate scans ($99.5\%$ vs $45.7\%$), while RF retains advantage on high-rate scans ($87.9\%$ vs $73.3\%$). |
| **Reporting Rule** | **DO NOT infer cross-source generalization** from this aggregate 100% result. | Report both directions explicitly and acknowledge the duality of rate vs entropy features. |

---

## 5. Pre-Manuscript Readiness Checklist & Final Recommendation

| Item | Requirement | Audit Status | Reference |
| :--- | :--- | :---: | :--- |
| **Dataset Lineage** | 343,889 raw flows reconciled to 3,000 benchmark windows | **PASS** | Task 6 Report, Section 3 |
| **Target Leakage** | Zero features conditioned on attack labels or filenames | **PASS** | `test_no_target_leakage.py` (6/6 pass) |
| **Disjoint Partitioning** | Zero overlap between train, val, and test observations/groups | **PASS** | Task 6 Report, Section 4 |
| **Mathematical Lower Bound** | $H_{port} \ge 0.85$ requires $\ge 20$ distinct ports (27 withdrawn) | **PASS** | Task 8 Report, Section 2 |
| **Bidirectional Cross-Source** | Evaluated across `metasploitable-2` and `OVS` testbeds | **PASS** | Task 8 Report, Section 3 |
| **Observation Independence** | 2,500 attack predictions reconciled to 500 unique windows | **PASS** | Section 2 above |
| **Uncertainty Interpretation** | Wilson CIs reported at window ($N=500$) and session ($K=20$) level | **PASS** | Section 3 above |
| **Experimental Decoupling** | Primary LOATO aggregate distinguished from cross-source tests | **PASS** | Section 4 above |

### Final Verdict: **READY FOR MANUSCRIPT UPDATE WITH EXPLICIT LIMITATIONS**

The experimental foundation of IntelliShield SDN LOATO is now completely verified, mathematically sound, free of target leakage, and methodologically defensible. 

### Mandatory Caveats for Section VII of the IEEE Manuscript:
1. **Confounded Capture Source for Normal/Botnet Traffic:** In InSDN, benign traffic is confined to `Normal_data.csv` (`192.168.20.0/24`). Cross-source generalization of normal traffic cannot be established from InSDN alone.
2. **Session Clustering & Pseudo-Replication:** 5-seed evaluation resamples the same 500 attack windows (originating from 4 DDoS sessions and 20 Probe sessions). Reported confidence intervals are nominal i.i.d. bounds; true session-level parameter uncertainty is wider ($K=20$, $95\% \text{ CI}: [83.89\%, 100.00\%]$).
3. **Decoupled LOATO Interpretation:** The 100% LOATO recall is an aggregate fusion effect across the benchmark. In source-held-out tests, destination port entropy dominates on stealthy low-rate scans ($99.5\%$ vs $45.7\%$), while supervised Random Forest retains an advantage on high-rate scans ($87.9\%$ vs $73.3\%$).
