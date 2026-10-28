# R3 — Digital Twin: Knowledge Base Q&A

**Related:** [../../02_Novelties/08_R3_Digital_Twin.md](../../02_Novelties/08_R3_Digital_Twin.md) · `R3_DIGITAL_TWIN.md` · `GLOSSARY.md`

Answers reflect the current `twin/` package. Twin-owned Mininet launch and live OpenFlow switch mutation are **not implemented** (fail-closed / out of snapshot-twin scope). R1 and R9 are **out of current project scope**.

> **PROJECT_DOCS copy** — adapted from `R3_QNA.md`. Novelty manuals: [`../../02_Novelties/`](../../02_Novelties/README.md). Quick viva bank: [`../08_Novelty_Questions.md`](../08_Novelty_Questions.md).

---

## Overview

R3 is a **snapshot-driven, read-only digital twin and validation plane**: it models the lab (profile, topology, S1–S5 plans), ingests completed experiment logs, replays expected vs observed events, computes snapshot deltas, and validates candidate detection thresholds and mitigation policies against ground truth before operator deployment. It does **not** control or mutate the live SDN switches.

---

## Architecture

```
SDN Network (Switches & Hosts)
         ↓
Controller Telemetry & Experiment Logs (CSV / JSONL)
         ↓
capture_snapshot  →  TwinObservation  →  diff_snapshots
         ↓
replay_scenario  |  simulate_whatif  |  evaluate_candidate_policy
         ↓
Validation Report (TP/FP/FN/TN · Collateral Impact · IEEE Quality Gates)
         ↓
SOC Monitoring Dashboard (#twin)
         ↓
Controlled Operator Approval Gateway (Explicit Approval Required)
         ↓ (Manual Export Only)
SDN Controller Configuration
```

---

## Q&A — Architecture, Novelty & Viva Concepts

**Q. Is Mininet “the digital twin”?**  
**A.** No. Mininet + `TrafficScheduler` are the **physical/emulated execution backend**. The twin is `twin/` (profile, plans, snapshot, diff, replay, candidate policy validation). Calling raw Mininet “the twin” is a conceptual mistake explicitly rejected in `twin/inventory.py`.

**Q. What fidelity level is claimed?**  
**A.** Level A (observational snapshot twin) and Level B (read-only live telemetry sync and plan-space what-if). Not Level 4 live hardware OpenFlow sync. Not Level 5 closed-loop automatic mutation.

**Q. Does the controller import the twin package?**  
**A.** No. `controller/flow_monitor.py` has zero twin imports. Complete architectural isolation is enforced and asserted by automated tests.

**Q. Can the twin launch S1–S5 attacks or inject network packets?**  
**A.** No. Twin simulation evaluates attack variations in parameter and plan space against active telemetry. It never transmits raw socket packets or floods the network.

**Q. What is a snapshot?**  
**A.** `capture_snapshot(logs_dir)` reads bounded telemetry logs from an experiment run, captures the network topology model, computes system metrics and baseline/attack statistics, writes `logs/twin/snapshots/<id>/`, and generates a `TwinObservation`.

**Q. What is Snapshot Diffing?**  
**A.** `diff_snapshots(base, compare)` computes structured telemetry and scenario deltas between two recorded runs: flow row count differences, attack window shifts, added/removed attack scenarios, baseline/attack packet rate deltas, and configuration fingerprint consistency. Accessible via `GET /api/digital-twin/snapshots/diff?base=...&compare=...`.

**Q. What is What-If Simulation?**  
**A.** Parameter-space simulation (`simulate_whatif` and `simulate_live_whatif`) that takes scenario parameters (duration, packet rate, target host) and calculates projected surge multipliers, load ratios, and severity impact against live or recorded baselines without resimulating raw packets.

**Q. What is Candidate Policy Validation?**  
**A.** `evaluate_candidate_policy(snapshot, candidate)` evaluates proposed packet rate thresholds, byte rate thresholds, and mitigation actions (`BLOCK`, `RATE_LIMIT`, `OBSERVE`) against ground-truth attack windows in recorded snapshot traces. It computes True Positives, False Positives, False Negatives, True Negatives, Precision, Recall, F1, and FPR.

**Q. How does the twin estimate impact on legitimate traffic?**  
**A.** By tracking False Positives (normal baseline flows that would be mistakenly triggered by the candidate threshold). It calculates collateral damage percentage:
$$\text{Collateral Damage \%} = \frac{\text{False Positives}}{\text{Total Normal Flows}} \times 100$$
and assigns a disruption severity rating (`NONE`, `LOW`, `MODERATE`, `HIGH`, `CRITICAL`).

**Q. Can the twin automatically apply a validated policy to the controller?**  
**A.** Absolutely not. The twin enforces a **Safe Feedback Workflow**:
- Validation reports are marked `approval_status: PENDING_OPERATOR_APPROVAL`.
- `can_auto_apply` is hardcoded to `False`.
- The twin generates a sanitized export payload that requires explicit operator review in the SOC Dashboard before manual application.

**Q. Does the twin overwrite trained production models?**  
**A.** No. Model candidates remain isolated in temporary twin directories and never overwrite `logs/models/*.pkl`.

**Q. Can the dashboard execute arbitrary shell commands via twin APIs?**  
**A.** No. There is no execution endpoint. POST `/api/digital-twin/exec` does not exist (returns 404/405). All snapshot and validation IDs are strictly validated to prevent directory traversal (`..`).

**Q. Which REST APIs exist for the Digital Twin?**  
**A.**
- `GET /api/digital-twin/stats`
- `GET /api/digital-twin/snapshots`
- `GET /api/digital-twin/snapshots/{id}`
- `GET /api/digital-twin/snapshots/diff?base=...&compare=...`
- `POST /api/digital-twin/policies/validate`
- `GET /api/digital-twin/policies/validations`
- `GET /api/digital-twin/policies/validations/{id}`
- `GET /api/digital-twin/replays`
- `GET /api/digital-twin/simulations`
- `GET /api/digital-twin/live/state`
- `POST /api/digital-twin/live/simulate`
- `GET /api/digital-twin/live/simulations`

**Q. How is the Digital Twin integrated into the SOC Dashboard?**  
**A.** Under the `#twin` route on the existing dashboard without duplicate interfaces. It includes explicit visual badges (`LIVE OBSERVATION`, `SIMULATION`, `RECORDED DATA`), a visual SDN topology and node inventory card, an interactive what-if attack simulator, a candidate policy validation form with confusion matrix outputs, and a snapshot diff tool.
