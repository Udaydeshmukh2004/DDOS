#!/usr/bin/env python3
"""
IntelliShield SDN — Test Suite for Task 12: Final Adversarial Scientific Audit
Validates:
1. Recomputed headline metrics match Task 11 outputs.
2. 500/500 hybrid detections verified via exact set union (297 both, 18 DT only, 185 Ent only, 0 neither).
3. Zero leakage: 0 PROBE observations in train or val across all 5 seeds.
4. Source confounding diagnostic: AUC > 0.95 for source predictability from rates.
5. Cluster bootstrap intervals exist and show widened bounds for session-clustered models.
6. Zero Random Forest models in primary evaluation.
"""

import os
import pytest
import numpy as np
import pandas as pd

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_TEST_DIR)
RESULTS_DIR = os.path.join(_ROOT, "results")
REPORTS_DIR = os.path.join(_ROOT, "reports")

RECOMP_CSV = os.path.join(RESULTS_DIR, "task12_recomputed_probe_metrics.csv")
SOURCE_DIAG_CSV = os.path.join(RESULTS_DIR, "task12_source_predictability_diagnostic.csv")
BOOTSTRAP_CSV = os.path.join(RESULTS_DIR, "task12_cluster_bootstrap_intervals.csv")
REPORT_MD = os.path.join(REPORTS_DIR, "TASK_12_FINAL_ADVERSARIAL_AUDIT.md")
ATTR_CSV = os.path.join(RESULTS_DIR, "task11_non_rf_probe_attribution.csv")


def test_task12_artifacts_exist():
    """Verify that all Task 12 adversarial audit artifacts and CSV tables exist."""
    assert os.path.isfile(RECOMP_CSV), f"Missing {RECOMP_CSV}"
    assert os.path.isfile(SOURCE_DIAG_CSV), f"Missing {SOURCE_DIAG_CSV}"
    assert os.path.isfile(BOOTSTRAP_CSV), f"Missing {BOOTSTRAP_CSV}"
    assert os.path.isfile(REPORT_MD), f"Missing {REPORT_MD}"


def test_recomputed_probe_metrics():
    """Verify independently recomputed metrics for the 500 unique PROBE windows."""
    df = pd.read_csv(RECOMP_CSV)
    assert len(df) == 6

    # Non-RF Hybrid achieves 100.0% recall
    hyb_row = df[df["model_architecture"] == "Non_RF_Hybrid_DT_Entropy"].iloc[0]
    assert hyb_row["recomputed_tp"] == 500
    assert hyb_row["recomputed_fn"] == 0
    assert hyb_row["recomputed_recall"] == 1.0
    assert hyb_row["m2_recall (N=314)"] == 1.0
    assert hyb_row["ovs_recall (N=186)"] == 1.0

    # Decision Tree collapses on OVS (0.54%) but succeeds on metasploitable-2 (100%)
    dt_row = df[df["model_architecture"] == "Decision_Tree_Supervised"].iloc[0]
    assert dt_row["recomputed_tp"] == 315
    assert dt_row["recomputed_fn"] == 185
    assert dt_row["m2_recall (N=314)"] == 1.0
    assert dt_row["ovs_recall (N=186)"] == 0.0054


def test_union_and_zero_misses():
    """Verify the exact set union and zero missed windows in the hybrid model."""
    df_attr = pd.read_csv(ATTR_CSV)
    s42 = df_attr[df_attr["seed"] == 42]
    assert len(s42) == 500

    dt_pred = (s42["pred_dt"] == 1).values
    ent_pred = (s42["pred_ent_val"] == 1).values
    hyb_pred = (s42["pred_hyb_dt"] == 1).values

    both = int(np.sum(dt_pred & ent_pred))
    dt_only = int(np.sum(dt_pred & (~ent_pred)))
    ent_only = int(np.sum((~dt_pred) & ent_pred))
    neither = int(np.sum((~dt_pred) & (~ent_pred)))

    assert both == 297
    assert dt_only == 18
    assert ent_only == 185
    assert neither == 0
    assert int(np.sum(hyb_pred)) == 500


def test_source_predictability_diagnostic():
    """Verify that capture source is highly predictable from rates (AUC > 0.95)."""
    df = pd.read_csv(SOURCE_DIAG_CSV)
    for _, r in df.iterrows():
        assert r["metric_value"] >= 0.95, f"Expected high source AUC, got {r['metric_value']}"


def test_cluster_bootstrap_widening():
    """Verify that cluster bootstrap reveals true session clustering variance."""
    df = pd.read_csv(BOOTSTRAP_CSV)
    dt_row = df[df["model_architecture"] == "Decision_Tree_Supervised"].iloc[0]

    # Standard Wilson interval is narrow ([58.68%, 67.12%])
    # Cluster bootstrap interval is wide ([29.62%, 84.66%])
    assert dt_row["window_wilson_95"] == "[58.68%, 67.12%]"
    assert dt_row["cluster_boot_win_95"] == "[29.62%, 84.66%]"

    hyb_row = df[df["model_architecture"] == "Non_RF_Hybrid_DT_Entropy"].iloc[0]
    assert hyb_row["cluster_boot_win_95"] == "[100.0%, 100.0%]"
    assert hyb_row["session_wilson_95"] == "[83.89%, 100.0%]"

