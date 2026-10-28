#!/usr/bin/env python3
"""Grouped Subsystem and Novelty Verification Runner."""

from __future__ import annotations

import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

suites = {
    "1. Foundation & Ops Profile (shared_contracts)": [
        "tests/test_shared_contracts_foundation.py",
        "tests/test_ops_confidence_calibration.py",
    ],
    "2. R4 Cross-Layer Correlation Engine": [
        "tests/test_correlation_inventory_r41.py",
        "tests/test_correlation_engine_r42.py",
        "tests/test_correlation_perf_r42.py",
        "tests/test_correlation_runtime_r43.py",
        "tests/test_correlation_dashboard_r44.py",
        "tests/test_correlation_hardening_r45.py",
        "tests/test_correlation_perf_r45.py",
        "tests/test_correlation_sensitivity_ablation_r45.py",
    ],
    "3. R6 Collaborative Fusion Engine": [
        "tests/test_fusion_adapters_r61.py",
        "tests/test_fusion_engine_r62.py",
        "tests/test_fusion_perf_r62.py",
        "tests/test_fusion_runtime_r63.py",
        "tests/test_fusion_dashboard_r64.py",
        "tests/test_fusion_hardening_r65.py",
    ],
    "4. R7 Multi-Stage Verification Gate": [
        "tests/test_verification_engine_r71.py",
        "tests/test_verification_golden_r72.py",
        "tests/test_verification_runtime_r73.py",
        "tests/test_verification_hardening_r74.py",
        "tests/test_verification_perf_r74.py",
    ],
    "5. R5 Explainable AI (XAI)": [
        "tests/test_xai_core_r51.py",
        "tests/test_xai_faithfulness_r55.py",
    ],
    "6. R5 Root Cause Analysis (RCA)": [
        "tests/test_rca_engine_r52.py",
        "tests/test_rca_runtime_r53.py",
        "tests/test_rca_dashboard_r54.py",
        "tests/test_rca_correctness_r55.py",
        "tests/test_r5_hardening_r55.py",
        "tests/test_r5_perf_r55.py",
    ],
    "7. R8 Policy-Aware Alerting Engine": [
        "tests/test_alerting_core_r81.py",
        "tests/test_alerting_policy_r82.py",
        "tests/test_alerting_runtime_r83.py",
        "tests/test_alerting_dashboard_r84.py",
        "tests/test_alerting_hardening_r85.py",
        "tests/test_alerting_perf_r85.py",
    ],
    "8. R3 Digital Twin (Level A Snapshot & Level B Live)": [
        "tests/test_twin_model_r31.py",
        "tests/test_twin_scenarios_r32.py",
        "tests/test_twin_validation_r33.py",
        "tests/test_twin_dataset_dashboard_r34.py",
        "tests/test_twin_acceptance_r35.py",
        "tests/test_twin_snapshot_replay_r36.py",
        "tests/test_twin_level_a_phase1.py",
        "tests/test_twin_level_a_phase3_ui.py",
        "tests/test_twin_level_a_acceptance.py",
        "tests/test_twin_live_level_b.py",
    ],
    "9. SSL Zero-Day Anomaly Detection": [
        "tests/test_ssl_zero_day.py",
    ],
    "10. Online AutoML & Retraining": [
        "tests/test_online_automl.py",
    ],
    "11. Baseline Pipeline & IEEE Metrics": [
        "tests/test_attack_type_classifier.py",
        "tests/test_mitigation_strategy_p04.py",
        "tests/test_rl_observation_p01.py",
        "tests/test_scenario4_p02.py",
        "tests/test_experiment_windows_p03.py",
        "tests/test_experiment_bundle_p05.py",
        "tests/test_ieee_metrics_p06.py",
        "tests/test_topology_status_v2.py",
    ],
    "12. SOC UI, Commands & Email Integration": [
        "tests/test_soc_ui_phase1.py",
        "tests/test_soc_ui_phase2.py",
        "tests/test_soc_ui_phase3.py",
        "tests/test_soc_ui_phase4.py",
        "tests/test_soc_ui_phase5.py",
        "tests/test_soc_ui_phase6.py",
        "tests/test_soc_ui_phase7.py",
        "tests/test_soc_ui_phase8.py",
        "tests/test_soc_ui_phase9.py",
        "tests/test_soc_ui_phase10.py",
        "tests/test_soc_ui_phase11.py",
        "tests/test_soc_ui_phase12.py",
        "tests/test_soc_ui_phase13.py",
        "tests/test_soc_ui_lab_email.py",
        "tests/test_email_alerts.py",
        "tests/test_dashboard_test_email_api.py",
        "tests/test_attack_to_email_integration.py",
        "tests/test_test_email_service.py",
        "tests/test_csv_log_io.py",
    ],
}

print("=" * 75)
print("INTELLISHIELD SDN — COMPREHENSIVE SUBSYSTEM & NOVELTY AUDIT")
print("=" * 75)

summary = {}
for name, files in suites.items():
    print(f"\n>>> Running: {name} ({len(files)} files)")
    ret = pytest.main(["-q", "--tb=line"] + files)
    status = "PASS" if ret == 0 else "FAIL"
    summary[name] = status
    print(f"--- RESULT: {name} -> [{status}] ---")

print("\n" + "=" * 75)
print("FINAL AUDIT SUMMARY TABLE:")
print("=" * 75)
all_pass = True
for name, status in summary.items():
    print(f"  [{status}] {name}")
    if status != "PASS":
        all_pass = False

print("=" * 75)
print("OVERALL VERDICT: " + ("ALL PASSED (100%)" if all_pass else "SOME SUITES FAILED"))
print("=" * 75)

sys.exit(0 if all_pass else 1)

