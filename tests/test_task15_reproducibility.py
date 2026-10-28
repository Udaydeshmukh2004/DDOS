"""
Task 15 Automated Test Suite: Final Reproducibility Package Audit
Verifies that the primary non-RF LOATO evaluation is fully reproducible via a single
documented command, verifies SHA256 checksums, manifest integrity, zero Random Forest
models, fold-by-fold grouped source AUC, and explicit limitation disclosures.
"""

import os
import json
import hashlib
import pytest
import numpy as np
import pandas as pd

REPORT_PATH = "reports/TASK_15_REPRODUCIBILITY_PACKAGE.md"
MANIFEST_PATH = "results/task15_reproducibility_manifest.json"
METRICS_PATH = "results/task15_reproduced_loato_metrics.csv"
ATTR_PATH = "results/task15_reproduced_probe_attribution.csv"
FOLDS_PATH = "results/task15_grouped_source_auc_folds.csv"
BENCHMARK_PATH = "data/authentic_insdn_leakage_free.csv"


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def test_task15_artifacts_exist():
    """Verify all Task 15 deliverables exist and are non-empty."""
    for path in [REPORT_PATH, MANIFEST_PATH, METRICS_PATH, ATTR_PATH, FOLDS_PATH]:
        assert os.path.exists(path), f"Missing artifact: {path}"
        assert os.path.getsize(path) > 100, f"Artifact {path} is empty or too small"


def test_manifest_structure_and_checksum():
    """Verify manifest schema, dataset checksums, and zero-RF assertion."""
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Check benchmark dataset
    bench_info = manifest["benchmark_dataset"]
    assert bench_info["total_windows"] == 3000
    assert bench_info["normal_windows"] == 1369
    assert bench_info["attack_windows"] == 1631
    actual_sha = compute_sha256(BENCHMARK_PATH)
    assert bench_info["sha256"] == actual_sha, "Benchmark SHA256 mismatch in manifest"

    # Check model architecture
    model_arch = manifest["model_architecture"]
    assert model_arch["random_forest_models_present"] is False, "Random Forest reported present in manifest!"
    assert "DecisionTreeClassifier" in model_arch["supervised_baseline"]
    assert "Non_RF_Hybrid_DT_Entropy" in model_arch["collaborative_hybrid"]

    # Check reproduced results
    results = manifest["reproduced_results"]
    assert results["probe_unique_windows"] == 500
    assert results["probe_unique_sessions"] == 20
    attr = results["probe_detection_attribution"]
    assert attr["both_dt_and_entropy"] == 297
    assert attr["dt_only_metasploitable2"] == 17
    assert attr["dt_only_ovs"] == 1
    assert attr["entropy_only_ovs"] == 185
    assert attr["total_union"] == 500
    assert attr["missed_windows"] == 0


def test_source_predictability_folds():
    """Verify fold-by-fold source predictability metrics and session grouping."""
    df_folds = pd.read_csv(FOLDS_PATH)
    assert len(df_folds) == 5, f"Expected 5 CV folds, got {len(df_folds)}"
    assert list(df_folds["fold"]) == [1, 2, 3, 4, 5]

    mean_dt = df_folds["dt_auc"].mean()
    assert pytest.approx(mean_dt, abs=0.01) == 0.8204

    # Ensure train and test sessions are positive for all folds
    assert (df_folds["train_sessions_count"] > 50).all()
    assert (df_folds["test_sessions_count"] > 0).all()


def test_window_1677_reproduced():
    """Verify exact metadata and hybrid decision reason for Window 1677."""
    df_attr = pd.read_csv(ATTR_PATH)
    w1677 = df_attr[df_attr["raw_window_id"] == 1677]
    assert len(w1677) == 1, "Window 1677 not found in reproduced attribution CSV"
    row = w1677.iloc[0]

    assert row["capture_source"] == "OVS"
    assert pytest.approx(row["port_entropy"], abs=1e-3) == 0.6135
    assert row["pred_ent_val"] == 0
    assert row["pred_ent_apr"] == 0
    assert row["pred_dt"] == 1
    assert row["pred_hyb_dt"] == 1
    assert "DT_HIGH_CONFIDENCE" in str(row["reason_hyb_dt"])
    assert row["attribution_category"] == "DT_ONLY_OVS"


def test_zero_rf_code_integrity():
    """Inspect reproduction script AST/content to ensure zero Random Forest usage."""
    with open("scripts/reproduce_task15_package.py", "r", encoding="utf-8") as f:
        code = f.read()

    assert "RandomForestClassifier" not in code, "Found RandomForestClassifier in reproduction script!"
    assert "from sklearn.ensemble import RandomForestClassifier" not in code


def test_report_disclosed_limitations():
    """Verify that the reproducibility report contains required limitation sections and conservative verdict."""
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        report = f.read()

    assert "VALIDATED FOR THIS BENCHMARK (WITH QUALIFICATIONS)" in report
    assert "Normal_data.csv" in report
    assert "20-Session" in report or "20 sessions" in report
    assert "83.89%" in report
    assert "universal environment invariance" in report.lower()
    assert "zero-day" in report.lower()

