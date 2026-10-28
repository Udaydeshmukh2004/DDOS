#!/usr/bin/env python3
"""
Test Suite for Task 17: Clean Rerun of Corrected LOATO Results
Verifies independent reproducibility, dataset purity, confusion matrix reconciliation,
four-way attribution, and session-level isolation.
"""

import os
import ast
import json
import hashlib
import pandas as pd
import pytest

_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_FILE_DIR) if os.path.basename(_FILE_DIR) == "tests" else _FILE_DIR

TASK17_DIR = os.path.join(_ROOT, "results", "task17_clean_rerun")
REPORTS_DIR = os.path.join(_ROOT, "reports")
DATA_DIR = os.path.join(_ROOT, "data")
SCRIPTS_DIR = os.path.join(_ROOT, "scripts")

EXPECTED_BENCHMARK_SHA256 = "30b49f285bd0d39c00dad9d93c5029b6fd4529c7c7993ec65956d8ab41207fc7"


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def test_task17_files_generated():
    """Verify all Task 17 output artifacts exist and are non-empty."""
    expected_files = [
        os.path.join(TASK17_DIR, "clean_loato_metrics.csv"),
        os.path.join(TASK17_DIR, "clean_probe_attribution.csv"),
        os.path.join(TASK17_DIR, "clean_seed42_test_predictions_all.csv"),
        os.path.join(TASK17_DIR, "clean_session_detections.csv"),
        os.path.join(TASK17_DIR, "clean_source_auc_folds.csv"),
        os.path.join(TASK17_DIR, "task17_manifest.json"),
        os.path.join(REPORTS_DIR, "TASK_17_CLEAN_RERUN_VERIFICATION.md")
    ]
    for fp in expected_files:
        assert os.path.exists(fp), f"Missing expected Task 17 artifact: {fp}"
        assert os.path.getsize(fp) > 0, f"Task 17 artifact is empty: {fp}"


def test_task17_source_dataset_integrity():
    """Verify authentic InSDN benchmark dataset integrity and hash."""
    benchmark_path = os.path.join(DATA_DIR, "authentic_insdn_leakage_free.csv")
    assert os.path.exists(benchmark_path)
    actual_hash = compute_sha256(benchmark_path)
    assert actual_hash == EXPECTED_BENCHMARK_SHA256, (
        f"Benchmark hash mismatch: expected {EXPECTED_BENCHMARK_SHA256}, got {actual_hash}"
    )


def test_task17_seed42_split_composition():
    """Verify Seed 42 PROBE test split has exactly 757 windows (500 attack, 257 normal)."""
    preds_path = os.path.join(TASK17_DIR, "clean_seed42_test_predictions_all.csv")
    df = pd.read_csv(preds_path)
    
    assert len(df) == 757, f"Expected 757 test windows, found {len(df)}"
    attack_df = df[df["ground_truth"] == 1]
    normal_df = df[df["ground_truth"] == 0]
    
    assert len(attack_df) == 500, f"Expected 500 attack windows, found {len(attack_df)}"
    assert len(normal_df) == 257, f"Expected 257 normal windows, found {len(normal_df)}"
    
    # Verify session counts
    attack_sessions = attack_df["session_group"].nunique()
    normal_sessions = normal_df["session_group"].nunique()
    assert attack_sessions == 20, f"Expected 20 attack sessions, found {attack_sessions}"
    assert normal_sessions == 75, f"Expected 75 normal sessions, found {normal_sessions}"


def test_task17_seed42_confusion_matrices():
    """Independently recompute confusion matrices from per-window predictions."""
    preds_path = os.path.join(TASK17_DIR, "clean_seed42_test_predictions_all.csv")
    df = pd.read_csv(preds_path)
    
    y_true = df["ground_truth"].values
    
    # 1. Decision Tree
    y_dt = df["pred_dt"].values
    tp_dt = int(((y_true == 1) & (y_dt == 1)).sum())
    fp_dt = int(((y_true == 0) & (y_dt == 1)).sum())
    tn_dt = int(((y_true == 0) & (y_dt == 0)).sum())
    fn_dt = int(((y_true == 1) & (y_dt == 0)).sum())
    assert (tp_dt, fp_dt, tn_dt, fn_dt) == (315, 0, 257, 185)
    
    # 2. A Priori Entropy (threshold = 0.85)
    y_ap = df["pred_ent_apr"].values
    tp_ap = int(((y_true == 1) & (y_ap == 1)).sum())
    fp_ap = int(((y_true == 0) & (y_ap == 1)).sum())
    tn_ap = int(((y_true == 0) & (y_ap == 0)).sum())
    fn_ap = int(((y_true == 1) & (y_ap == 0)).sum())
    assert (tp_ap, fp_ap, tn_ap, fn_ap) == (415, 0, 257, 85)
    
    # 3. Hybrid (DT + Tuned Entropy)
    y_hyb = df["pred_hyb_dt"].values
    tp_hyb = int(((y_true == 1) & (y_hyb == 1)).sum())
    fp_hyb = int(((y_true == 0) & (y_hyb == 1)).sum())
    tn_hyb = int(((y_true == 0) & (y_hyb == 0)).sum())
    fn_hyb = int(((y_true == 1) & (y_hyb == 0)).sum())
    assert (tp_hyb, fp_hyb, tn_hyb, fn_hyb) == (500, 1, 256, 0)
    
    # Check rates
    assert tp_hyb / (tp_hyb + fn_hyb) == 1.0
    assert round(fp_hyb / (fp_hyb + tn_hyb), 4) == 0.0039


def test_task17_apriori_entropy_detection_rate():
    """Verify a priori entropy detects strictly 415/500 windows (83.00%)."""
    preds_path = os.path.join(TASK17_DIR, "clean_seed42_test_predictions_all.csv")
    df = pd.read_csv(preds_path)
    attack_df = df[df["ground_truth"] == 1]
    
    apriori_hits = attack_df["pred_ent_apr"].sum()
    assert apriori_hits == 415, f"Expected 415 a priori entropy hits, got {apriori_hits}"
    
    # Check by source
    m2_df = attack_df[attack_df["capture_source"] == "metasploitable-2"]
    ovs_df = attack_df[attack_df["capture_source"] == "OVS"]
    
    m2_hits = m2_df["pred_ent_apr"].sum()
    ovs_hits = ovs_df["pred_ent_apr"].sum()
    
    assert (m2_hits, len(m2_df)) == (230, 314)
    assert (ovs_hits, len(ovs_df)) == (185, 186)


def test_task17_four_way_attribution_exact_counts():
    """Verify four-way attribution partition: 297 both, 17 DT m2, 1 DT ovs, 185 Ent ovs, 0 missed."""
    attr_path = os.path.join(TASK17_DIR, "clean_probe_attribution.csv")
    df = pd.read_csv(attr_path)
    
    assert len(df) == 500, f"Expected 500 rows in attribution CSV, got {len(df)}"
    
    both = df[df["attribution_category"] == "BOTH_DT_AND_ENTROPY"]
    dt_m2 = df[df["attribution_category"] == "DT_ONLY_METASPLOITABLE2"]
    dt_ovs = df[df["attribution_category"] == "DT_ONLY_OVS"]
    ent_ovs = df[df["attribution_category"] == "ENTROPY_ONLY_OVS"]
    
    assert len(both) == 297
    assert len(dt_m2) == 17
    assert len(dt_ovs) == 1
    assert len(ent_ovs) == 185
    assert len(both) + len(dt_m2) + len(dt_ovs) + len(ent_ovs) == 500
    
    # Verify sources for each category
    assert (both["capture_source"] == "metasploitable-2").all()
    assert (ent_ovs["capture_source"] == "OVS").all()
    assert (dt_m2["capture_source"] == "metasploitable-2").all()
    assert (dt_ovs["capture_source"] == "OVS").all()
    assert dt_ovs.iloc[0]["raw_window_id"] == 1677


def test_task17_session_detections_all_positive():
    """Verify all 20 held-out PROBE sessions are detected by the hybrid."""
    sess_path = os.path.join(TASK17_DIR, "clean_session_detections.csv")
    df = pd.read_csv(sess_path)
    
    assert len(df) == 20
    assert (df["session_detected"] == 1).all()


def test_task17_manifest_and_no_random_forest():
    """Verify manifest exists, and confirm no Random Forest in scripts or outputs."""
    manifest_path = os.path.join(TASK17_DIR, "task17_manifest.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    
    assert manifest["reproduction_mode"] == "INDEPENDENT_CLEAN_RERUN"
    
    # Verify metrics CSV does not contain Random Forest
    metrics_path = os.path.join(TASK17_DIR, "clean_loato_metrics.csv")
    df_metrics = pd.read_csv(metrics_path)
    archs = df_metrics["model_architecture"].unique()
    for arch in archs:
        assert "RandomForest" not in arch
        assert "Random_Forest" not in arch
    
    # Verify script AST has no RandomForestClassifier import
    script_path = os.path.join(SCRIPTS_DIR, "rerun_task17_clean_loato.py")
    with open(script_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                assert alias.name != "RandomForestClassifier", "RandomForestClassifier import found!"
        elif isinstance(node, ast.Name):
            assert node.id != "RandomForestClassifier", "RandomForestClassifier reference found!"
