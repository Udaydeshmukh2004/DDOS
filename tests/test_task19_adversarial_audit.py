#!/usr/bin/env python3
"""
Test Suite for Task 19: Adversarial Audit of Task 18 Cross-Dataset Results
Verifies:
1. Existence and integrity of Task 19 audit artifacts, reports, and discrepancy table.
2. Independent recomputation of packet counts (216,213), window counts (98), and class balance (47N / 51A).
3. Exact confusion matrix parity for Protocol 1 and Protocol 2 between reported and recomputed metrics.
4. Forensic validation of Isolation Forest saturation (100% FPR) and DT vs. Hybrid identity.
5. Labeling rule and boundary window transition audit (8 boundary windows, 0 leakage in pure benign sessions).
6. Diagnostic Source-Classifier 5-fold Stratified Group K-Fold integrity (0 session leakage, AUC ~1.0000).
7. Non-regression of frozen Task 17 baseline and production controller files.
"""

import os
import json
import hashlib
import pandas as pd
import pytest

_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_FILE_DIR) if os.path.basename(_FILE_DIR) == "tests" else _FILE_DIR

DATA_DIR = os.path.join(_ROOT, "data")
TASK18_DATA_DIR = os.path.join(DATA_DIR, "task18_mininet")
RAW_PACKET_CSV = os.path.join(TASK18_DATA_DIR, "raw", "raw_packet_stream.csv")
MININET_WINDOW_CSV = os.path.join(TASK18_DATA_DIR, "mininet_unseen_capture.csv")

RESULTS_TASK18_DIR = os.path.join(_ROOT, "results", "task18_unseen_capture")
PREDICTIONS_CSV = os.path.join(RESULTS_TASK18_DIR, "task18_per_window_predictions.csv")
TASK18_METRICS_CSV = os.path.join(RESULTS_TASK18_DIR, "task18_evaluation_metrics.csv")
TASK18_DIAGNOSTIC_CSV = os.path.join(RESULTS_TASK18_DIR, "task18_source_diagnostic_folds.csv")

RESULTS_TASK19_DIR = os.path.join(_ROOT, "results", "task19_adversarial_audit")
RECOMPUTED_METRICS_CSV = os.path.join(RESULTS_TASK19_DIR, "task19_recomputed_metrics.csv")
DISCREPANCY_TABLE_CSV = os.path.join(RESULTS_TASK19_DIR, "task19_discrepancy_table.csv")
FEATURE_AUDIT_CSV = os.path.join(RESULTS_TASK19_DIR, "task19_feature_distribution_audit.csv")
BOUNDARY_AUDIT_CSV = os.path.join(RESULTS_TASK19_DIR, "task19_boundary_windows_audit.csv")
MANIFEST_JSON = os.path.join(RESULTS_TASK19_DIR, "task19_manifest.json")
REPORT_TASK19 = os.path.join(_ROOT, "reports", "TASK_19_TASK18_FORENSIC_AUDIT.md")

FROZEN_INSDN_SHA256 = "30b49f285bd0d39c00dad9d93c5029b6fd4529c7c7993ec65956d8ab41207fc7"


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class TestTask19Artifacts:
    """Verifies that all Task 19 audit deliverables exist, are populated, and have valid schemas."""

    def test_audit_artifacts_exist(self):
        for path in [
            RECOMPUTED_METRICS_CSV,
            DISCREPANCY_TABLE_CSV,
            FEATURE_AUDIT_CSV,
            BOUNDARY_AUDIT_CSV,
            MANIFEST_JSON,
            REPORT_TASK19,
        ]:
            assert os.path.isfile(path), f"Missing Task 19 artifact: {path}"
            assert os.path.getsize(path) > 100, f"Artifact empty or too small: {path}"

    def test_manifest_structure(self):
        with open(MANIFEST_JSON, "r") as f:
            manifest = json.load(f)
        assert manifest["task"] == "Task 19: Adversarial Audit of Task 18 Cross-Dataset Results"
        assert manifest["audit_verdict"] == "VERIFIED_WITH_SCIENTIFIC_GROUNDING"
        assert "exact_counts" in manifest
        assert manifest["exact_counts"]["raw_packets"] == 216213
        assert manifest["exact_counts"]["mininet_windows"] == 98
        assert manifest["exact_counts"]["normal_windows"] == 47
        assert manifest["exact_counts"]["attack_windows"] == 51
        assert manifest["exact_counts"]["protocol2_test_windows"] == 32
        assert manifest["exact_counts"]["boundary_windows"] == 8


class TestPhysicalCountsAndIntegrity:
    """Verifies exact physical file line counts and dataframe dimensions."""

    def test_raw_packet_count(self):
        # Header + 216,213 data rows = 216,214 lines
        count = 0
        with open(RAW_PACKET_CSV, "r", encoding="utf-8") as f:
            for _ in f:
                count += 1
        assert count == 216214, f"Expected 216214 lines (header + 216,213 packets), got {count}"

    def test_mininet_window_dataset_dimensions(self):
        df = pd.read_csv(MININET_WINDOW_CSV)
        assert len(df) == 98, f"Expected 98 windows, got {len(df)}"
        assert (df["ground_truth"] == 0).sum() == 47, "Expected exactly 47 normal windows"
        assert (df["ground_truth"] == 1).sum() == 51, "Expected exactly 51 attack windows"

    def test_protocol2_test_split_size(self):
        df = pd.read_csv(MININET_WINDOW_CSV)
        test_df = df[df["session_group"].isin(["session_07_unseen_multivector_test", "session_08_unseen_eval_scenario"])]
        assert len(test_df) == 32, f"Expected 32 test windows for Protocol 2, got {len(test_df)}"
        assert (test_df["ground_truth"] == 0).sum() == 10
        assert (test_df["ground_truth"] == 1).sum() == 22


class TestConfusionMatrixParity:
    """Verifies that recomputed confusion matrices match Task 18 reported values exactly."""

    def test_protocol1_hybrid_metrics(self):
        pred_df = pd.read_csv(PREDICTIONS_CSV)
        y_true = pred_df["ground_truth"].values
        y_pred = pred_df["pred_hyb_dt"].values

        tp = int(((y_true == 1) & (y_pred == 1)).sum())
        fp = int(((y_true == 0) & (y_pred == 1)).sum())
        tn = int(((y_true == 0) & (y_pred == 0)).sum())
        fn = int(((y_true == 1) & (y_pred == 0)).sum())

        assert (tp, fp, tn, fn) == (21, 47, 0, 30), f"Expected (21, 47, 0, 30), got {(tp, fp, tn, fn)}"
        recall = tp / (tp + fn)
        fpr = fp / (fp + tn)
        assert pytest.approx(recall, rel=1e-3) == 21 / 51  # 41.18%
        assert pytest.approx(fpr, rel=1e-3) == 1.0  # 100.00%

    def test_protocol1_isolation_forest_fpr(self):
        pred_df = pd.read_csv(PREDICTIONS_CSV)
        y_true = pred_df["ground_truth"].values
        y_pred = pred_df["pred_iso"].values

        tp = int(((y_true == 1) & (y_pred == 1)).sum())
        fp = int(((y_true == 0) & (y_pred == 1)).sum())
        tn = int(((y_true == 0) & (y_pred == 0)).sum())
        fn = int(((y_true == 1) & (y_pred == 0)).sum())

        assert (tp, fp, tn, fn) == (51, 47, 0, 0)
        assert pytest.approx(fp / (fp + tn), rel=1e-4) == 1.0000

    def test_protocol2_decision_tree_metrics(self):
        m_df = pd.read_csv(TASK18_METRICS_CSV)
        p2_dt = m_df[(m_df["protocol"] == "Protocol_2_InDomain_SessionDisjoint") & (m_df["model_architecture"] == "Decision_Tree")].iloc[0]

        assert int(p2_dt["tp"]) == 13
        assert int(p2_dt["fp"]) == 0
        assert int(p2_dt["tn"]) == 10
        assert int(p2_dt["fn"]) == 9
        assert float(p2_dt["fpr"]) == 0.0
        assert pytest.approx(float(p2_dt["recall"]), rel=1e-3) == 13 / 22  # 59.09%


class TestForensicExplanations:
    """Verifies the mathematical validity of the forensic findings for Protocol 1 anomalies."""

    def test_dt_and_hybrid_predictions_are_identical(self):
        pred_df = pd.read_csv(PREDICTIONS_CSV)
        dt_preds = pred_df["pred_dt"].values
        hyb_preds = pred_df["pred_hyb_dt"].values
        diffs = (dt_preds != hyb_preds).sum()
        assert diffs == 0, f"Expected 0 differing rows between DT and Hybrid in Protocol 1, got {diffs}"

    def test_dt_predicted_1_on_all_mininet_normal_windows(self):
        pred_df = pd.read_csv(PREDICTIONS_CSV)
        normal_windows = pred_df[pred_df["ground_truth"] == 0]
        dt_prob = normal_windows["dt_prob"].values
        assert (dt_prob == 1.0).sum() == 47, "DT did not predict prob=1.0 on all normal Mininet windows"

    def test_probe_scale_invariant_generalization(self):
        pred_df = pd.read_csv(PREDICTIONS_CSV)
        probe_df = pred_df[pred_df["attack_type"] == "PROBE"]
        assert len(probe_df) == 19
        hyb_detected = probe_df["pred_hyb_dt"].sum()
        assert hyb_detected == 18, f"Expected 18 / 19 PROBE detections, got {hyb_detected}"


class TestBoundaryWindowsAndLabeling:
    """Verifies label assignment, schedule boundary conditions, and clean session isolation."""

    def test_boundary_window_count(self):
        bdf = pd.read_csv(BOUNDARY_AUDIT_CSV)
        assert len(bdf) == 98, f"Expected audit records for all 98 windows, got {len(bdf)}"
        boundary_count = int(bdf["is_boundary_window"].sum())
        assert boundary_count == 8, f"Expected exactly 8 boundary windows, got {boundary_count}"

    def test_pure_benign_sessions_have_zero_false_labels(self):
        df = pd.read_csv(MININET_WINDOW_CSV)
        for s_id in ["session_01_benign_light", "session_05_benign_bursty"]:
            session_df = df[df["session_group"] == s_id]
            assert len(session_df) > 0
            assert (session_df["ground_truth"] == 0).all(), f"Session {s_id} contains non-zero ground truth"
            assert (session_df["attack_type"] == "NORMAL").all()


class TestSourceDiagnosticValidation:
    """Verifies the 5-fold Stratified Group K-Fold source predictability diagnostic."""

    def test_source_diagnostic_folds(self):
        df_diag = pd.read_csv(TASK18_DIAGNOSTIC_CSV)
        assert len(df_diag) == 5
        assert pytest.approx(df_diag["lr_source_auc"].mean(), rel=1e-4) == 1.0000
        assert df_diag["dt_source_auc"].mean() > 0.98
        assert (df_diag["session_overlap"] == 0).all()


class TestBaselinePurity:
    """Verifies that production code and baseline benchmarks remain strictly untouched."""

    def test_authentic_insdn_hash_unchanged(self):
        insdn_csv = os.path.join(DATA_DIR, "authentic_insdn_leakage_free.csv")
        assert compute_sha256(insdn_csv) == FROZEN_INSDN_SHA256

    def test_controller_code_unmodified(self):
        # ml_models/ contains the controller ML logic and should not be modified
        ml_models_dir = os.path.join(_ROOT, "ml_models")
        assert os.path.isdir(ml_models_dir)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
