#!/usr/bin/env python3
"""
IntelliShield SDN — Test Suite for Task 11: Non-Random-Forest Evaluation
Validates:
1. Complete exclusion of Random Forest from all primary evaluation tables and metrics.
2. Presence and evaluation of supervised Decision Tree (Decision_Tree_Supervised).
3. Clear distinction between Unsupervised Machine Learning (Isolation Forest) and
   Rule-Based / Threshold Heuristics (Entropy Standalone / A Priori).
4. Preservation of LOATO protocol (held-out attack excluded from training and tuning).
5. Unique observation and session metrics reporting with Wilson 95% CIs.
6. Attribution of PROBE detections: DT high confidence vs Port Entropy Override.
"""

import os
import math
import pytest
import pandas as pd
import numpy as np

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_TEST_DIR)
RESULTS_DIR = os.path.join(_ROOT, "results")
REPORTS_DIR = os.path.join(_ROOT, "reports")

METRICS_CSV = os.path.join(RESULTS_DIR, "task11_non_rf_loato_metrics.csv")
UNIQUE_CSV = os.path.join(RESULTS_DIR, "task11_non_rf_unique_summary.csv")
ATTR_CSV = os.path.join(RESULTS_DIR, "task11_non_rf_probe_attribution.csv")
SESS_CSV = os.path.join(RESULTS_DIR, "task11_non_rf_session_detections.csv")
REPORT_MD = os.path.join(REPORTS_DIR, "TASK_11_NON_RF_EVALUATION.md")


def test_task11_artifacts_exist():
    """Verify that all Task 11 non-RF artifacts and CSV tables were generated."""
    assert os.path.isfile(METRICS_CSV), f"Missing {METRICS_CSV}"
    assert os.path.isfile(UNIQUE_CSV), f"Missing {UNIQUE_CSV}"
    assert os.path.isfile(ATTR_CSV), f"Missing {ATTR_CSV}"
    assert os.path.isfile(SESS_CSV), f"Missing {SESS_CSV}"
    assert os.path.isfile(REPORT_MD), f"Missing {REPORT_MD}"


def test_zero_random_forest_models():
    """Verify that Random Forest is completely excluded from the primary evaluation."""
    df_metrics = pd.read_csv(METRICS_CSV)
    models = df_metrics["model_architecture"].unique()

    # Assert NO model name contains Random Forest
    for m in models:
        assert "Random_Forest" not in m, f"Forbidden model found: {m}"
        assert "RF" not in m or "Non_RF" in m, f"Forbidden RF reference in model: {m}"

    # Assert supervised Decision Tree IS present
    assert "Decision_Tree_Supervised" in models

    # Assert Entropy rule-based and Isolation Forest are present
    assert "Entropy_Rule_Based_APriori" in models
    assert "Entropy_Rule_Based_ValTuned" in models
    assert "Isolation_Forest_Unsupervised" in models
    assert "Non_RF_Hybrid_DT_Entropy" in models


def test_unsupervised_vs_heuristic_paradigm_distinction():
    """Verify clear distinction between unsupervised ML and rule-based heuristics."""
    df_metrics = pd.read_csv(METRICS_CSV)

    ent_apr_rows = df_metrics[df_metrics["model_architecture"] == "Entropy_Rule_Based_APriori"]
    assert (ent_apr_rows["paradigm"] == "Rule-Based Heuristic").all()

    ent_val_rows = df_metrics[df_metrics["model_architecture"] == "Entropy_Rule_Based_ValTuned"]
    assert (ent_val_rows["paradigm"] == "Rule-Based Heuristic (Val-Tuned)").all()

    iso_rows = df_metrics[df_metrics["model_architecture"] == "Isolation_Forest_Unsupervised"]
    assert (iso_rows["paradigm"] == "Unsupervised Machine Learning").all()

    dt_rows = df_metrics[df_metrics["model_architecture"] == "Decision_Tree_Supervised"]
    assert (dt_rows["paradigm"] == "Supervised Machine Learning (Single Tree)").all()


def test_unique_probe_attribution_and_complementarity():
    """Verify per-window attribution on 500 unique PROBE windows and source breakdown."""
    df_attr = pd.read_csv(ATTR_CSV)
    s42 = df_attr[df_attr["seed"] == 42]
    assert len(s42) == 500

    # Hybrid DT + Entropy achieves 100% recall
    assert s42["pred_hyb_dt"].sum() == 500

    # Exact decision reasons:
    # 415 Port Entropy Overrides (H >= 0.85)
    # 85 DT High Confidence (p >= 0.75)
    counts = s42["reason_hyb_dt"].value_counts()
    assert counts["PORT_ENTROPY_OVERRIDE (H >= 0.85)"] == 415
    assert counts["DT_HIGH_CONFIDENCE (p >= 0.75)"] == 85

    # Decision Tree collapses on low-rate OVS scans
    m2 = s42[s42["capture_source"] == "metasploitable-2"]
    ovs = s42[s42["capture_source"] == "OVS"]
    assert len(m2) == 314
    assert len(ovs) == 186

    # On metasploitable-2 (high rate), DT recall is 100%
    assert m2["pred_dt"].sum() == 314
    # On OVS (low rate), single DT collapses to 1/186 (0.54%)
    assert ovs["pred_dt"].sum() == 1

    # Entropy detects 185/186 on OVS
    assert ovs["pred_ent_val"].sum() == 185


def test_session_level_detections_and_wilson_ci():
    """Verify session detection outcomes across 20 unique PROBE sessions."""
    df_sess = pd.read_csv(SESS_CSV)
    assert len(df_sess) == 20

    m2_sess = df_sess[df_sess["capture_source"] == "metasploitable-2"]
    ovs_sess = df_sess[df_sess["capture_source"] == "OVS"]
    assert len(m2_sess) == 6
    assert len(ovs_sess) == 14

    # Non-RF Hybrid detects 20/20 sessions
    assert df_sess["sess_det_hyb_dt"].sum() == 20

    # Decision tree alone detects only 7/20 sessions (all 6 metasploitable-2, 1 OVS)
    assert df_sess["sess_det_dt"].sum() == 7
    assert m2_sess["sess_det_dt"].sum() == 6
    assert ovs_sess["sess_det_dt"].sum() == 1

    # Wilson 95% CI bounds for 20/20 sessions
    df_unique = pd.read_csv(UNIQUE_CSV)
    hyb_row = df_unique[df_unique["model_architecture"] == "Non_RF_Hybrid_DT_Entropy"].iloc[0]
    assert hyb_row["session_ci_95"] == "[83.89%, 100.0%]"
    assert hyb_row["session_recall"] == 1.0
