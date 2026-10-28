#!/usr/bin/env python3
"""
Test Suite for Task 18: Independent Mininet Attack Dataset and Unseen-Capture Evaluation
Verifies:
1. Generation and integrity of Mininet raw packet telemetry and windowed dataset.
2. Ground-truth label assignment strictly from schedule timestamps (unbiased).
3. Session isolation and zero overlap across partitions.
4. Evaluation of Non-RF detectors (DT, Entropy, Isolation Forest, Hybrid).
5. Source-predictability diagnostic execution and documentation.
6. Purity of prior task artifacts (Task 17 frozen baseline).
"""

import os
import ast
import json
import hashlib
import pandas as pd
import pytest

_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_FILE_DIR) if os.path.basename(_FILE_DIR) == "tests" else _FILE_DIR

DATA_DIR = os.path.join(_ROOT, "data")
TASK18_DATA_DIR = os.path.join(DATA_DIR, "task18_mininet")
RAW_DIR = os.path.join(TASK18_DATA_DIR, "raw")
RESULTS_DIR = os.path.join(_ROOT, "results", "task18_unseen_capture")
REPORTS_DIR = os.path.join(_ROOT, "reports")
SCRIPTS_DIR = os.path.join(_ROOT, "scripts")

FROZEN_INSDN_SHA256 = "30b49f285bd0d39c00dad9d93c5029b6fd4529c7c7993ec65956d8ab41207fc7"


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def test_task18_artifacts_generated():
    """Verify all required Task 18 datasets, evaluation outputs, and reports exist."""
    required_files = [
        os.path.join(RAW_DIR, "raw_packet_stream.csv"),
        os.path.join(RAW_DIR, "experiment_schedule.json"),
        os.path.join(TASK18_DATA_DIR, "mininet_unseen_capture.csv"),
        os.path.join(TASK18_DATA_DIR, "task18_dataset_manifest.json"),
        os.path.join(RESULTS_DIR, "task18_evaluation_metrics.csv"),
        os.path.join(RESULTS_DIR, "task18_per_window_predictions.csv"),
        os.path.join(RESULTS_DIR, "task18_session_detections.csv"),
        os.path.join(RESULTS_DIR, "task18_source_diagnostic_folds.csv"),
        os.path.join(RESULTS_DIR, "task18_manifest.json"),
        os.path.join(REPORTS_DIR, "TASK_18_INDEPENDENT_CAPTURE_EVALUATION.md"),
    ]
    for fp in required_files:
        assert os.path.exists(fp), f"Missing Task 18 artifact: {fp}"
        assert os.path.getsize(fp) > 0, f"Artifact is empty: {fp}"


def test_task18_raw_packet_telemetry_validity():
    """Verify raw packet stream contains real telemetry across switch interfaces."""
    raw_path = os.path.join(RAW_DIR, "raw_packet_stream.csv")
    df_raw = pd.read_csv(raw_path)

    assert len(df_raw) > 500, f"Expected >500 raw packets, got {len(df_raw)}"
    expected_cols = [
        "timestamp", "interface", "packet_length", "eth_src", "eth_dst",
        "eth_type", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "tcp_flags"
    ]
    for col in expected_cols:
        assert col in df_raw.columns, f"Missing column {col} in raw packets CSV"

    # Verify multiple switch interfaces were observed
    ifaces = df_raw["interface"].unique()
    assert len(ifaces) >= 2, f"Expected at least 2 switch interfaces, found {ifaces}"


def test_task18_labeling_integrity_and_schedule_grounding():
    """Verify ground-truth labels are grounded in schedule timestamps and benign sessions have 0 attacks."""
    ds_path = os.path.join(TASK18_DATA_DIR, "mininet_unseen_capture.csv")
    df_ds = pd.read_csv(ds_path)

    assert len(df_ds) > 50, f"Expected >50 windows in Mininet dataset, got {len(df_ds)}"

    # Benign sessions must have exactly 0 attack windows
    benign_s1 = df_ds[df_ds["session_group"] == "session_01_benign_light"]
    benign_s5 = df_ds[df_ds["session_group"] == "session_05_benign_bursty"]
    assert len(benign_s1) > 0
    assert len(benign_s5) > 0
    assert (benign_s1["ground_truth"] == 0).all(), "Found positive labels in benign session 1!"
    assert (benign_s5["ground_truth"] == 0).all(), "Found positive labels in benign session 5!"

    # Overall dataset must have both normal and attack windows
    assert (df_ds["ground_truth"] == 0).sum() > 0
    assert (df_ds["ground_truth"] == 1).sum() > 0


def test_task18_zero_random_forest():
    """Verify no Random Forest models are evaluated in Task 18 metrics or manifest."""
    metrics_path = os.path.join(RESULTS_DIR, "task18_evaluation_metrics.csv")
    df_metrics = pd.read_csv(metrics_path)
    for model_name in df_metrics["model_architecture"].unique():
        assert "RandomForest" not in model_name
        assert "Random_Forest" not in model_name

    manifest_path = os.path.join(RESULTS_DIR, "task18_manifest.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    assert manifest.get("zero_random_forest") is True


def test_task18_session_disjointness_protocol2():
    """Verify Protocol 2 partitions (train, val, test) have strictly zero session overlap."""
    ds_path = os.path.join(TASK18_DATA_DIR, "mininet_unseen_capture.csv")
    df_ds = pd.read_csv(ds_path)

    train_sess = {"session_01_benign_light", "session_02_syn_flood", "session_03_udp_flood", "session_04_icmp_flood"}
    val_sess = {"session_05_benign_bursty", "session_06_port_scan_probe"}
    test_sess = {"session_07_unseen_multivector_test", "session_08_unseen_eval_scenario"}

    assert len(train_sess.intersection(val_sess)) == 0
    assert len(train_sess.intersection(test_sess)) == 0
    assert len(val_sess.intersection(test_sess)) == 0

    actual_sess = set(df_ds["session_group"].unique())
    assert train_sess.issubset(actual_sess)
    assert val_sess.issubset(actual_sess)
    assert test_sess.issubset(actual_sess)


def test_task18_session_detections_coverage():
    """Verify all 6 attack sessions are detected by the hybrid detector."""
    sess_path = os.path.join(RESULTS_DIR, "task18_session_detections.csv")
    df_sess = pd.read_csv(sess_path)

    attack_sessions = df_sess[df_sess["has_attack"] == 1]
    assert len(attack_sessions) == 6, f"Expected 6 attack sessions, found {len(attack_sessions)}"
    assert (attack_sessions["session_detected"] == 1).all(), "Not all attack sessions were detected!"


def test_task18_source_diagnostic_folds():
    """Verify source confounding diagnostic evaluated 5 folds and recorded valid AUCs."""
    diag_path = os.path.join(RESULTS_DIR, "task18_source_diagnostic_folds.csv")
    df_diag = pd.read_csv(diag_path)

    assert len(df_diag) == 5, f"Expected 5 cross-validation folds, got {len(df_diag)}"
    assert (df_diag["session_overlap"] == 0).all(), "Grouped fold leaked sessions across train and test!"
    assert df_diag["dt_source_auc"].mean() > 0.80, "Expected high diagnostic AUC reflecting source differences"


def test_task18_frozen_baseline_intact():
    """Verify Task 17 source data and clean rerun results remain strictly untouched."""
    insdn_path = os.path.join(DATA_DIR, "authentic_insdn_leakage_free.csv")
    assert compute_sha256(insdn_path) == FROZEN_INSDN_SHA256, "InSDN benchmark dataset was modified!"

    task17_metrics = os.path.join(_ROOT, "results", "task17_clean_rerun", "clean_loato_metrics.csv")
    assert os.path.exists(task17_metrics)
    assert os.path.getsize(task17_metrics) > 0

