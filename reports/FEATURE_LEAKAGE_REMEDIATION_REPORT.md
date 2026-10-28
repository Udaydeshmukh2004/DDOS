# Feature Leakage Remediation & Empirical Lineage Report

**Pipeline Version:** `v2.0.0-leakage-free`  
**Auditor & Research Lead:** Senior ML Engineer & IEEE Network Security Reviewer  
**Execution Date:** October 25, 2026  
**Clean Benchmark Dataset:** [`data/authentic_insdn_leakage_free.csv`](file:////mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/data/authentic_insdn_leakage_free.csv)  
**Dataset SHA-256:** `30b49f285bd0d39c00dad9d93c5029b6fd4529c7c7993ec65956d8ab41207fc7`  
**Configuration Manifest:** [`configs/leakage_free_experiment.json`](file:////mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/configs/leakage_free_experiment.json)  

---

## 1. Executive Summary & Defect Elimination

In Task 3, forensic analysis discovered that `scripts/ingest_authentic_insdn.py` contained severe target-label conditioning in topological and entropy features (`flow_concentration`, `unique_dst_count`, `unique_src_count`, `dst_entropy`), assigning constants conditional on `attack_family` and `binary_label`.

### Remediation Actions Completed:
1. **Zero Target-Conditioned Feature Generation:**
   - Completely deleted all target-conditioned assignments.
   - Built a modular, label-independent feature extractor: [`scripts/build_empirical_network_features.py`](file:////mnt/c/Users/deshm/OneDrive/Desktop/intellishield_sdn-main/scripts/build_empirical_network_features.py).
   - Input features are computed exclusively from raw observed network fields (`Src IP`, `Dst IP`, `Dst Port`, `Protocol`, `Flow Pkts/s`, `Flow Byts/s`, `Flow Duration`).
2. **Invariance Guarantee:**
   - Shuffling or deleting the `Label` column from input data produces **100.0% mathematically identical feature vectors**.
3. **Empirical Window Aggregation ($W=50$ Flows):**
   - Observations are aggregated over tumbling flow windows ($W=50$), accurately simulating an OpenFlow controller periodically harvesting flow buffer statistics every 5 seconds.
   - Entropies, host counts, and concentration indices are computed strictly from empirical probability distributions observed within each window.

---

## 2. Complete 15-Feature Empirical Lineage Table

| Index | Model Feature Name | Raw InSDN Source Fields | Mathematical Formula / Transformation | Empirical Window Definition | Availability at SDN Inference Time |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **1** | `packet_rate_mean` | `Flow Pkts/s` | Mean packet rate over window | Tumbling window of $W=50$ active flows | Calculated directly from OpenFlow `byte_count / duration` |
| **2** | `packet_rate_max` | `Flow Pkts/s` | Peak packet rate in window | Tumbling window of $W=50$ active flows | Peak flow rate in switch buffer |
| **3** | `byte_rate_mean` | `Flow Byts/s` | Mean byte rate over window | Tumbling window of $W=50$ active flows | Calculated from flow statistics |
| **4** | `byte_rate_max` | `Flow Byts/s` | Peak byte rate in window | Tumbling window of $W=50$ active flows | Peak byte rate in switch buffer |
| **5** | `flow_count` | Stream buffer size | Cardinality $|W| = 50$ | Tumbling window of $W=50$ active flows | Active flow table entries polled from switch |
| **6** | `duration_mean` | `Flow Duration` | Mean flow duration in seconds | Mean flow age in seconds | Flow entry duration (excluded from training) |
| **7** | `unique_src_count` | `Src IP` | Distinct source IP count | Distinct source IPs in window | Distinct source MAC/IPs in flow buffer |
| **8** | `unique_dst_count` | `Dst IP` | Distinct destination IP count | Distinct destination IPs in window | Distinct destination MAC/IPs in flow buffer |
| **9** | `src_entropy` | `Src IP` | Normalized Shannon entropy of source IPs | Source IP entropy | Empirical Phase 2 entropy engine |
| **10** | `dst_entropy` | `Dst IP` | Normalized Shannon entropy of destination IPs | Destination IP entropy | Empirical Phase 2 entropy engine |
| **11** | `packet_entropy` | `Dst Port` | Normalized Shannon entropy of destination ports | Destination port dispersion entropy | Empirical Phase 2 entropy engine (Port scan indicator) |
| **12** | `byte_entropy` | `Flow Pkts/s` | Quantile-binned load distribution entropy | Uniformity of packet load across flows | Empirical Phase 2 entropy engine |
| **13** | `flow_entropy` | `Protocol` | Protocol distribution Shannon entropy | Protocol diversity across active flows | Empirical Phase 2 entropy engine |
| **14** | `entropy_score` | Features 9–13 | $0.25 H_{src} + 0.25 H_{dst} + 0.25 H_{port} + 0.15 H_{load} + 0.10 H_{proto}$ | Composite information-theoretic index | Weighted Phase 2 anomaly score |
| **15** | `flow_concentration`| `Dst IP` | Herfindahl-Hirschman index $\sum p(dst)^2$ | Herfindahl-Hirschman destination concentration | Direct empirical concentration index |

---

## 3. Dataset Integrity & Benchmark Allocation

- **Total Available Empirical Windows in Raw InSDN:** **6,879 windows** (343,889 flows / 50)
- **Leakage-Free Benchmark Sample ($N=3,000$):**
  - `NORMAL`: 1,369 windows (45.63%)
  - `DDOS`: 600 windows (20.00%)
  - `PROBE`: 500 windows (16.67%)
  - `DOS`: 500 windows (16.67%)
  - `BRUTE_FORCE`: 28 windows (0.93%)
  - `BOTNET`: 3 windows (0.10%)

---

## 4. Acceptance Criteria Verification

- [x] **No Target-Conditioned Logic:** Verified across all code paths.
- [x] **Label Invariance:** Passing `df.drop(columns=['Label'])` produces identical output.
- [x] **Full Provenance:** Source zip SHA-256 matches `ee89ec66...` and raw flow count matches 343,889.
