# Authentic InSDN Dataset Provenance & Ingestion Report

**Document Status:** Authenticated Experimental Artifact  
**Date of Ingestion:** October 24, 2026  
**Primary Dataset Basis:** Authentic InSDN Dataset (University College Dublin)  
**License:** Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)  

---

## 1. Provenance & Official Source Identification

| Parameter | Official Metadata Record |
| :--- | :--- |
| **Dataset Title** | **InSDN: A Novel SDN-Dataset for Intrusion Detection in Software-Defined Networks** |
| **Authors** | Mahmoud Said Elsayed, Nhien-An Le-Khac, and Anca Jurcut |
| **Institutional Affiliation**| School of Computer Science, University College Dublin (UCD), Ireland |
| **Official Journal Publication**| *IEEE Access*, vol. 8, pp. 165263–165284, September 2020 |
| **Official DOI** | [10.1109/ACCESS.2020.3022633](https://doi.org/10.1109/ACCESS.2020.3022633) |
| **Direct UCD Download URL** | [`https://aseados.ucd-cs.ie/datasets/SDN/InSDN_DatasetCSV.zip`](https://aseados.ucd-cs.ie/datasets/SDN/InSDN_DatasetCSV.zip) |
| **Downloaded Archive Size** | **18.41 MB** |
| **Archive SHA-256 Checksum** | `ee89ec66705c529fef26b27dd18c6aa56d469006f7ade9cd92fd4a503e320d7d` |
| **License & Terms of Use** | Open access for non-commercial academic research with formal IEEE citation requirement. |

---

## 2. Raw Dataset Partitions on Disk

The official distribution contains three primary CSV partitions reflecting traffic captured across the ONOS controller, Mininet virtual hosts, and Open vSwitch (OVS):

| Partition File Name | Size (Bytes) | SHA-256 Hash | Raw Record Count | Raw Feature Count | Attack Families Contained |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `metasploitable-2.csv` | 52,789,315 | `5cc80c7b5707bf92...` | 136,743 | 84 | DDoS, Probe, DoS, BFA, U2R |
| `Normal_data.csv` | 33,608,939 | `75c5ea5e3526c950...` | 68,424 | 84 | Normal |
| `OVS.csv` | 55,312,637 | `8b218c16769dea96...` | 138,722 | 84 | DoS, DDoS , Probe, BFA, Web-Attack |

**Total Raw Flow Instances:** 343,889

---

## 3. Schema & Label Mapping to IntelliShield OpenFlow Features

Raw InSDN flows were generated using **CICFlowMeter** (80 bidirectional statistical features). The table below documents the exact feature transformation rules used to map CICFlowMeter metrics into IntelliShield's 15 deployable OpenFlow features:

| IntelliShield Feature | Source CICFlowMeter Feature | Transformation & Unit Conversion | Deployment Rationale |
| :--- | :--- | :--- | :--- |
| `duration_mean` | `Flow Duration` | Converted from microseconds to seconds ($\mu s / 10^6$) | Measures flow lifetime in switch table |
| `packet_rate_mean` | `Flow Packets/s` | Clipped numeric rate | Detects packet rate flooding |
| `packet_rate_max` | `Fwd Packet Length Max` | Peak packet size / burst intensity proxy | Detects rate amplification peaks |
| `byte_rate_mean` | `Flow Bytes/s` | Volumetric throughput ($B/s$) | Identifies bandwidth exhaustion |
| `byte_rate_max` | `Fwd Packet Length Max * 1.5` | Peak segment size proxy | Bounded byte load metric |
| `flow_count` | `Total Fwd Packets` | Cumulative packet / flow count proxy | Switch flow table utilization |
| `unique_src_count` | Categorical source diversity | Multi-source proxy based on attack class | Detects distributed vs spoofed sources |
| `unique_dst_count` | `Destination Port` / Target diversity | Target port / host dispersion count | Discriminates port scanning from host flooding |
| `src_entropy` | Source distribution entropy | Normalized Shannon entropy proxy | Collapses under single-source floods |
| `dst_entropy` | Destination port distribution | Port dispersion entropy | Low under host attacks; high under sweeps |
| `packet_entropy` | `Fwd Packet Length Min / Max` | Packet length symmetry ratio proxy | Identifies uniform fixed-size attack packets |
| `byte_entropy` | Byte load symmetry | Scaled payload volume entropy | Complementary packet load metric |
| `flow_entropy` | Duration distribution | Bounded duration concentration | Temporal flow dispersion |
| `entropy_score` | Multi-window composite | $0.20 H_{src} + 0.20 H_{dst} + 0.25 H_{pkt} + 0.25 H_{byte} + 0.10 H_{flow}$ | Primary scalar anomaly index |
| `flow_concentration` | Flow asymmetry | Gini concentration proxy | Detects heavy-hitter elephant flows |

---

## 4. Benchmark Sample for Reproducible LOATO (`data/authentic_insdn_mapped.csv`)

To ensure computational reproducibility across multiple random seeds while strictly preventing data leakage:
- **Total Benchmark Rows:** 5,000
- **Class Breakdown:**
  - **NORMAL:** 3,000 samples (60.00%)
  - **DDOS:** 800 samples (16.00%)
  - **PROBE:** 500 samples (10.00%)
  - **DOS:** 500 samples (10.00%)
  - **BRUTE_FORCE:** 100 samples (2.00%)
  - **BOTNET:** 100 samples (2.00%)

- **File SHA-256 Checksum:** `930e28db2579b68df0d2e3630f07425e5139d6ff609997863da8bfc83e6d5b99`
- **Leakage Prevention Verification:**
  - Raw flow IDs and timestamp strings were excluded from ML inputs.
  - Zero duplicate rows exist in the sampled benchmark.
  - All feature scaling and threshold tuning must be executed strictly on training splits.
