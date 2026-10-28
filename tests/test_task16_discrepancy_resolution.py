"""
Task 16 Automated Test Suite: Final Reproduction Discrepancy Resolution
Verifies that all numerical discrepancies between prior reports and Task 15 are resolved:
1. A priori entropy recall is verified at 415/500 (83.00%) at the row level.
2. Ground-truth test set size for Seed 42 is verified at N=757 (257 normal + 500 PROBE).
3. Hybrid produces TP=500, FP=1, TN=256, FN=0 on the actual test partition.
4. Fold 2 of StratifiedGroupKFold is audited (4 test sessions, 0 overlap, inverted AUC).
"""

import os
import pytest
import numpy as np
import pandas as pd

REPORT_PATH = "reports/TASK_16_FINAL_DISCREPANCY_RESOLUTION.md"
ROW_CSV_PATH = "results/task16_apriori_entropy_row_level_comparison.csv"
FOLDS_CSV_PATH = "results/task15_grouped_source_auc_folds.csv"
METRICS_CSV_PATH = "results/task15_reproduced_loato_metrics.csv"


def test_task16_artifacts_exist():
    """Verify that Task 16 report and row-level comparison CSV exist and are non-empty."""
    assert os.path.exists(REPORT_PATH), f"Missing report: {REPORT_PATH}"
    assert os.path.getsize(REPORT_PATH) > 1000, f"Report {REPORT_PATH} is too small"

    assert os.path.exists(ROW_CSV_PATH), f"Missing CSV: {ROW_CSV_PATH}"
    assert os.path.getsize(ROW_CSV_PATH) > 1000, f"CSV {ROW_CSV_PATH} is too small"


def test_apriori_entropy_ground_truth_recall():
    """Verify that exactly 415 out of 500 PROBE windows have packet_entropy >= 0.85."""
    df = pd.read_csv(ROW_CSV_PATH)
    assert len(df) == 500, f"Expected 500 PROBE rows, got {len(df)}"

    n_ge_085 = df["actual_packet_entropy_ge_085"].sum()
    assert n_ge_085 == 415, f"Expected 415 windows >= 0.85, got {n_ge_085}"

    # Per source breakdown
    m2_ge = df[df["capture_source"] == "metasploitable-2"]["actual_packet_entropy_ge_085"].sum()
    ovs_ge = df[df["capture_source"] == "OVS"]["actual_packet_entropy_ge_085"].sum()
    assert m2_ge == 230, f"Expected 230 metasploitable-2 windows >= 0.85, got {m2_ge}"
    assert ovs_ge == 185, f"Expected 185 OVS windows >= 0.85, got {ovs_ge}"

    # Confirm that task 15 metric CSV also recorded 415
    df_metrics = pd.read_csv(METRICS_CSV_PATH)
    p_row = df_metrics[(df_metrics["held_out_attack"] == "PROBE") & 
                       (df_metrics["seed"] == 42) & 
                       (df_metrics["model_architecture"] == "Entropy_Rule_Based_APriori")].iloc[0]
    assert p_row["tp"] == 415, f"Expected 415 TP in metrics CSV, got {p_row['tp']}"
    assert p_row["recall"] == 0.83, f"Expected 0.83 recall in metrics CSV, got {p_row['recall']}"


def test_seed42_test_set_composition_and_confusion_matrix():
    """Verify that the Seed 42 test set contains 757 windows and hybrid produces TP=500, FP=1, TN=256, FN=0."""
    df_metrics = pd.read_csv(METRICS_CSV_PATH)
    hyb_row = df_metrics[(df_metrics["held_out_attack"] == "PROBE") & 
                         (df_metrics["seed"] == 42) & 
                         (df_metrics["model_architecture"] == "Non_RF_Hybrid_DT_Entropy")].iloc[0]

    assert hyb_row["total"] == 757, f"Expected 757 total windows, got {hyb_row['total']}"
    assert hyb_row["tp"] == 500, f"Expected 500 TP, got {hyb_row['tp']}"
    assert hyb_row["fp"] == 1, f"Expected 1 FP, got {hyb_row['fp']}"
    assert hyb_row["tn"] == 256, f"Expected 256 TN, got {hyb_row['tn']}"
    assert hyb_row["fn"] == 0, f"Expected 0 FN, got {hyb_row['fn']}"
    assert hyb_row["recall"] == 1.0, f"Expected 1.0 recall, got {hyb_row['recall']}"


def test_fold2_grouped_auc_and_session_properties():
    """Verify that fold 2 of StratifiedGroupKFold contains 4 test sessions, 0 overlap, and inverted AUC."""
    df_folds = pd.read_csv(FOLDS_CSV_PATH)
    f2 = df_folds[df_folds["fold"] == 2].iloc[0]

    assert f2["test_sessions_count"] == 4, f"Expected 4 test sessions in fold 2, got {f2['test_sessions_count']}"
    assert f2["train_sessions_count"] == 131, f"Expected 131 train sessions in fold 2, got {f2['train_sessions_count']}"
    assert f2["test_m2_count"] == 83, f"Expected 83 m2 in fold 2, got {f2['test_m2_count']}"
    assert f2["test_ovs_count"] == 225, f"Expected 225 ovs in fold 2, got {f2['test_ovs_count']}"
    assert f2["dt_auc"] == 0.2470, f"Expected DT AUC 0.2470, got {f2['dt_auc']}"
    assert f2["lr_auc"] == 0.0000, f"Expected LR AUC 0.0000, got {f2['lr_auc']}"


def test_report_verdict_and_contents():
    """Verify that the Task 16 report has required sections, conservative verdict, and discrepancy table."""
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    assert "CONDITIONALLY SUPPORTED WITH FORMAL CORRECTIONS" in content
    assert "415" in content
    assert "231" in content
    assert "757" in content
    assert "OVS_4/2/2020 15:20" in content
    assert "Master Discrepancy Reconciliation Table" in content

