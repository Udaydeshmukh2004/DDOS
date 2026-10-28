# Leave-One-Attack-Type-Out (LOATO) Validation Report: IntelliShield SDN

**Auditor:** Independent Experimental Auditor & Skeptical Reviewer  
**Date:** October 24, 2026  
**Target Repository:** IntelliShield SDN  
**Dataset Basis:** `data/insdn_benchmark_mapped.csv` (Synthetic Parametric Stress Test)  
**Evaluation Protocol:** 5-Fold Multi-Seed Evaluation (Seeds: 42, 101, 2026, 777, 999)  

---

## 1. Executive Summary: What LOATO Proves (and What It Does Not)

The Leave-One-Attack-Type-Out (LOATO) evaluation was designed to test whether supervised machine learning models, statistical entropy detectors, and hybrid architectures can detect **previously unseen attack vectors** when trained exclusively on other attack types.

> [!IMPORTANT]
> **Essential Disclosure on Dataset Provenance:**  
> The LOATO experiments reported herein were executed on **`data/insdn_benchmark_mapped.csv`**, which is a **synthetic parametric simulation** generated from mathematical distributions (Gamma, Normal, Beta, Uniform) based on statistical ranges published in Elsayed et al. (*IEEE Access 2020*).  
> **This evaluation constitutes a controlled synthetic stress test. It MUST NOT be claimed as empirical proof of zero-day detection on live physical network traffic.**

---

## 2. Experimental Protocol & Class Partitions

In each scenario, one entire attack category is completely purged from the training set. The model is trained on the remaining attack categories and benign traffic, then tested on the unseen attack category alongside benign test traffic.

| Scenario | Held-Out Unseen Attack | Training Partition Composition | Test Partition Composition | Held-Out Sample Count |
| :--- | :--- | :--- | :--- | :---: |
| **Scenario A** | **TCP SYN Flood** | Benign (325) + UDP Flood (50) + Probe Scan (50) = **425 samples** | Benign (325) + Unseen SYN Flood (75) = **400 samples** | 75 |
| **Scenario B** | **UDP Flood** | Benign (325) + SYN Flood (75) + Probe Scan (50) = **450 samples** | Benign (325) + Unseen UDP Flood (50) = **375 samples** | 50 |
| **Scenario C** | **Probe / Port Scan**| Benign (325) + SYN Flood (75) + UDP Flood (50) = **450 samples** | Benign (325) + Unseen Probe Scan (50) = **375 samples** | 50 |

### Leakage Verification for LOATO:
- **Feature Scaling:** `StandardScaler` was fit strictly on the training partition (`X_tr`), containing only the non-held-out classes.
- **Threshold Tuning:** The entropy threshold was computed strictly from the training benign distribution (5th percentile of normal traffic entropy). **No held-out attack samples were used in model fitting, hyperparameter selection, or threshold calibration.**

---

## 3. Recomputed Multi-Seed Experimental Results

The table below presents the mean and standard deviation across five distinct random seeds ($S = \{42, 101, 2026, 777, 999\}$):

| Scenario (Held-Out Vector) | Detector Architecture | Attack Recall (Mean $\pm$ Std) | Precision (Mean $\pm$ Std) | F1-Score (Mean $\pm$ Std) | False Positive Rate (FPR) | Status / Empirical Finding |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Scenario A: Unseen SYN Flood** | Supervised Random Forest | **$100.0\% \pm 0.0\%$** | $100.0\% \pm 0.0\%$ | $100.0\% \pm 0.0\%$ | $0.00\%$ | High volumetric rate learned from UDP flood generalises to SYN flood. |
| Scenario A: Unseen SYN Flood | Statistical Entropy Standalone | **$100.0\% \pm 0.0\%$** | $58.1\% \pm 1.2\%$ | $73.5\% \pm 0.9\%$ | $15.46\%$ | Collapsed destination entropy flags 100% of SYN floods, with benign FP penalty. |
| Scenario A: Unseen SYN Flood | **Uncertainty-Gated Hybrid** | **$100.0\% \pm 0.0\%$** | **$100.0\% \pm 0.0\%$** | **$100.0\% \pm 0.0\%$** | **$0.00\%$** | Supervised RF is highly confident ($P \ge 0.75$), achieving clean detection. |
| **Scenario B: Unseen UDP Flood** | Supervised Random Forest | **$84.0\% \pm 2.0\%$** | $100.0\% \pm 0.0\%$ | $91.3\% \pm 1.1\%$ | $0.00\%$ | **RF misses $16.0\%$ of UDP floods** due to byte/packet length variations unseen in SYN floods. |
| Scenario B: Unseen UDP Flood | Statistical Entropy Standalone | **$100.0\% \pm 0.0\%$** | $47.6\% \pm 1.5\%$ | $64.5\% \pm 1.2\%$ | $15.46\%$ | Single-target destination collapse flags all UDP attack vectors. |
| Scenario B: Unseen UDP Flood | **Uncertainty-Gated Hybrid** | **$100.0\% \pm 0.0\%$** | **$100.0\% \pm 0.0\%$** | **$100.0\% \pm 0.0\%$** | **$0.00\%$** | **Hybrid recovers the $16\%$ missed attacks** via entropy fallback in the uncertain zone. |
| **Scenario C: Unseen Probe / Scan**| Supervised Random Forest | **$2.4\% \pm 0.8\%$** | $100.0\% \pm 0.0\%$ | **$4.7\% \pm 1.5\%$** | $0.00\%$ | **CATASTROPHIC FAILURE:** Low packet rates (~5 pkt/s) mimic benign interactive traffic. |
| Scenario C: Unseen Probe / Scan| Statistical Entropy (Train 5th %) | **$0.0\% \pm 0.0\%$** | $0.0\% \pm 0.0\%$ | $0.0\% \pm 0.0\%$ | $5.00\%$ | **Conservative threshold misses scan:** Single-server normal queries depress threshold. |
| Scenario C: Unseen Probe / Scan| Statistical Entropy (Fixed 0.65) | **$100.0\% \pm 0.0\%$** | $47.6\% \pm 1.5\%$ | $64.5\% \pm 1.2\%$ | $15.46\%$ | Relaxed threshold catches destination spread, but incurs 15.46% benign false alarm rate. |
| Scenario C: Unseen Probe / Scan| Uncertainty-Gated Hybrid | **$0.0\% - 12.0\%$** | $100.0\% \pm 0.0\%$ | $0.0\% - 21.4\%$ | $0.00\%$ | RF's extreme confidence ($P < 0.25$) that rate is normal bypasses the entropy gate. |

---

## 4. Deep Forensic Analysis of the Probe/Scan Failure Mode

The most significant finding of this audit is the failure mode in **Scenario C (Unseen Probe / Port Scan)**:

### Why Supervised ML Fails ($2.4\%$ Recall):
- Random Forest models trained on TCP SYN Floods ($1,000+\text{ pkt/s}$) and UDP Floods ($1,600+\text{ pkt/s}$) learn that "DDoS = high packet rate and high flow count."
- Low-rate reconnaissance and port scanning operates at **$4 - 15\text{ pkt/s}$**, which falls squarely within the distribution of legitimate interactive network traffic ($2 - 12\text{ pkt/s}$).
- Consequently, the supervised model assigns a near-zero attack probability ($P_{RF} < 0.05$) to probe scans, failing to classify 48 out of 50 attack samples.

### The Entropy Threshold Dilemma:
- When the entropy threshold is calibrated conservatively using the 5th percentile of normal traffic ($\theta \approx 0.35$ to avoid false alarms on legitimate single-server DNS/DB traffic), composite entropy for probe scans ($\approx 0.55$) is higher than $\theta$. **Recall drops to $0.0\%$.**
- When the threshold is relaxed to $\theta = 0.65$, entropy recall reaches **$100.0\%$**, but the False Positive Rate on benign single-destination queries increases to **$15.46\%$**.
- **Crucial Architectural Lesson:** Composite scalar entropy ($H_{comp}$) is an inadequate discriminator for port scans. Port scans require **directional entropy**—specifically tracking destination port entropy ($H_{dport}$) or unique destination counts ($\text{unique\_dst\_count} \ge 10$) alongside source concentration.

---

## 5. Auditor Recommendations for Manuscript Revision

1. **Re-label Section Title:** Change "Zero-Day Attack Generalization" to **"Out-of-Distribution Synthetic Stress Test (LOATO)"**.
2. **Disclose Synthetic Origin:** Explicitly disclose that LOATO was conducted on mathematically mapped distributions from InSDN, not captured PCAPs.
3. **Report the Probe Scan Failure Honestly:** Remove any claim that the uncertainty-gated hybrid seamlessly solves stealthy reconnaissance without trade-offs. Highlight the $2.4\%$ supervised recall collapse as an open research challenge and document the directional entropy requirement.
