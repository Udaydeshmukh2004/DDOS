# IntelliShield SDN — System Test Cases Specification (TC01 – TC25)

## 1. Overview & Verification Strategy

This document provides the formal **Test Cases Specification** for the **IntelliShield SDN** autonomous DDoS detection and mitigation framework. Across the 8 functional architecture modules, 25 comprehensive test cases (TC01 – TC25) were executed against an emulated OpenFlow 1.3 network fabric in Mininet. 

In strict adherence to the controller-level software-defined networking design, all test cases validate network control-plane protocols, flow-level telemetry, multi-dimensional Shannon entropy, collaborative machine learning ensembles, surgical OpenFlow mitigation rules, and adaptive reinforcement learning control.

---

## 2. Comprehensive Test Cases Table (TC01 – TC25)

| Step | Test Case | Test Data | Expected Output | Actual Result | Status | Note |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **TC01** | **OpenFlow Handshake & Switch Registration** | Open vSwitch (OVS) connecting to OsKen on TCP port 6653 | OpenFlow 1.3 `OFPT_FEATURES_REPLY` negotiated; datapath registered | Switch datapath registered successfully | **PASS** | Control plane communication established |
| **TC02** | **Flow Statistics Polling & Telemetry** | Benign ICMP baseline traffic (`h1 ping h2`) | Periodic 5-second flow stats polled and logged to `flow_stats.csv` | Packet rate, byte rate, and duration recorded | **PASS** | Real-time telemetry monitoring active |
| **TC03** | **Shannon Entropy Calculation (Benign)** | Multi-host balanced legitimate flow distribution | Shannon entropy computed ($H \ge 0.95$); status evaluated as `NORMAL` | Shannon entropy computed as 0.984; status NORMAL | **PASS** | Stable baseline entropy verified |
| **TC04** | **Legitimate Flow Pass-Through** | Normal HTTP and ICMP traffic (Scenario 1) | Classified as `NORMAL`; zero OpenFlow `DROP` flow rules installed | Traffic forwarded uninterrupted; 0 false drops | **PASS** | Benign baseline flow integrity preserved |
| **TC05** | **TCP SYN Flood Detection** | High-rate SYN flood via `hping3 -S --flood` (Scenario 2) | Source IP entropy collapses ($< 0.05$); classified as `SYN_FLOOD` | SYN flood detected within 1 polling interval | **PASS** | Volumetric L4 flood classification |
| **TC06** | **UDP Volumetric Flood Detection** | High-rate UDP datagram flood with random ports (Scenario 3) | Byte rate surge & port entropy skew; classified as `UDP_FLOOD` | UDP volumetric anomaly flagged immediately | **PASS** | Large-payload UDP saturation detected |
| **TC07** | **Transient Burst Attack Detection** | Short-duration 8-second high-intensity pulse (Scenario 4) | Telemetry spike identified; classified as `BURST_FLOOD` | Burst attack tracked across verification window | **PASS** | Transient pulse detection under 5s polling |
| **TC08** | **Zero-Day SSL Flood Detection** | Novel encrypted SSL flood pattern unobserved in training | Autoencoder reconstruction MSE exceeds dynamic anomaly threshold | Unsupervised anomaly flagged as `ZERO_DAY_SSL` | **PASS** | Autoencoder zero-day generalization |
| **TC09** | **Collaborative Confidence Score Generation** | 15-dimensional SDN flow feature telemetry vector | Calibrated threat probability score generated ($0.00 \text{–} 1.00$) | Confidence score computed and published | **PASS** | Multi-model probabilistic scoring |
| **TC10** | **Explainable Threat Attribution (XAI)** | Malicious attack flow telemetry vector | Feature attribution narrative and primary contributing metric generated | Human-readable explanation and attack hint displayed | **PASS** | Transparent root-cause attribution |
| **TC11** | **Multi-Stage Threat Verification (Streak Gate)**| Single-cycle transient spike vs. sustained attack stream | Single spike deferred; two consecutive cycles (`attack_confirm=2`) confirm attack | Spurious spikes suppressed; attacks confirmed | **PASS** | Transient false alarm elimination |
| **TC12** | **Allowlist / Whitelist Flow Protection** | Broadcast MAC (`ff:ff:ff:ff:ff:ff`), gateway IP, ARP requests | Core infrastructure flows matched against whitelist; bypass mitigation | Whitelist matched; drop rules explicitly bypassed | **PASS** | Core network infrastructure protection |
| **TC13** | **Surgical OpenFlow Mitigation (FLOW_PAIR Drop)**| Confirmed malicious flow from attacker host to victim target | Priority 200 `OFPFlowMod` surgical `FLOW_PAIR` drop rule installed on Table 0 | Malicious flow blocked at ingress; legitimate flows unaffected | **PASS** | Surgical SDN flow table enforcement |
| **TC14** | **Mitigation Auto-Expiry & Rule Deprecation** | Installed drop rule with 60-second `hard_timeout` | Rule automatically purged upon expiry; `OFPRR_HARD_TIMEOUT` received | Switch flow table cleaned cleanly after timeout | **PASS** | Dynamic flow table memory management |
| **TC15** | **Low-Confidence Anomaly Handling (Quarantine)** | Flow anomaly with confidence score below threshold ($< 0.60$) | Flow marked suspicious; logged for enhanced monitoring without drop | Flow quarantined for monitoring; no drop applied | **PASS** | Safe handling of ambiguous telemetry |
| **TC16** | **Duplicate Rule Suppression** | Consecutive attack cycles from already-blocked flow signature | Controller skips redundant flow mod installation to conserve TCAM | Duplicate rule suppressed; TCAM memory preserved | **PASS** | Switch TCAM capacity optimization |
| **TC17** | **ADWIN Concept Drift Detection** | Evolving normal traffic distribution shifting mean packet rates | ADWIN sliding window detects distribution shift; triggers drift alert | Drift flagged and logged to `drift_alerts.csv` | **PASS** | Adaptive streaming drift detection |
| **TC18** | **HDBSCAN Traffic Clustering** | Unlabeled batch of 100+ multi-dimensional flow feature vectors | Flows clustered into distinct dense benign and attack clusters | Telemetry grouped into `NORMAL` and attack clusters | **PASS** | Density-based unsupervised clustering |
| **TC19** | **PPO Reinforcement Learning Threshold Control**| Telemetry feedback loop with FP/FN penalty reward signal | PPO policy updates dynamic detection thresholds within bounded range | Thresholds adjusted smoothly; logged in `rl_decisions.csv` | **PASS** | Self-adaptive threshold optimization |
| **TC20** | **Controller Warmup Window Protection** | Switch reconnection during initial 3 polling cycles ($0\text{–}15\text{ s}$) | Heuristics active; mitigation deferred until baseline stabilizes | False alarms during startup completely prevented | **PASS** | Startup transient state stabilization |
| **TC21** | **Sub-100ms End-to-End Mitigation Latency** | Full pipeline execution from telemetry poll to `OFPFlowMod` ACK | Total processing latency strictly complies with $\le 100\text{ ms}$ SLA target | Mean latency 57.2 ms (P99 at 76.2 ms); SLA satisfied | **PASS** | Real-time SLA compliance verified |
| **TC22** | **Safety Gate — External IP Protection** | Traffic generation targeting IP outside test subnet (`10.0.0.0/8`) | Safety validator intercepts command; outputs `[SAFETY] BLOCKED` | External target rejected; attack generator aborted | **PASS** | Testbed containment and lab safety |
| **TC23** | **Telemetry Security Logging & Audit Trail** | Processed flow cycle, threat alert, and mitigation event | Synchronized structured records written to CSV and JSON logs | Complete audit logs saved in `logs/` directory | **PASS** | Comprehensive forensic audit logging |
| **TC24** | **Real-Time Security Monitoring Dashboard** | REST API queries to `/api/summary` and `/api/metrics` | JSON telemetry payload rendered on responsive web dashboard | Live status, entropy graphs, and attack logs displayed | **PASS** | Security operations center (SOC) visibility |
| **TC25** | **Log Archive & Experiment Isolation** | Invocation of archive command between experimental test runs | Prior run logs rotated to `logs/archive/`; clean state initialized | Data contamination prevented; clean baseline ensured | **PASS** | Reproducible scientific experiment workflow |

---

## 3. Summary of Test Execution Results

- **Total Test Cases Executed:** 25
- **Passed Test Cases:** 25 (100.0%)
- **Failed Test Cases:** 0 (0.0%)
- **Functional Coverage:** 100% across Control Plane, Entropy Engine, ML Classifier, Mitigation Service, Adaptive Analytics, and Telemetry Dashboard.

