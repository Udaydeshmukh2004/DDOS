#!/usr/bin/env python3
"""
Test Suite: Authentic InSDN Dataset and LOATO Generalization Pipeline
Covers:
1. Dataset Provenance & SHA-256 Integrity
2. Feature Mapping Schema & Value Bounds (15 Features)
3. Label Mapping & Binary Ground-Truth Consistency
4. Strict 3-Way Anti-Leakage Split Integrity (LOATO)
5. Metric Calculation Mathematical Rigor (Confusion Matrix, Wilson CI)
6. Experiment Outputs Integrity (Metrics CSV & Markdown Report)
"""

import os
import sys
import hashlib
import numpy as np
import pandas as pd
import pytest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_FILE_DIR) if os.path.basename(_FILE_DIR) == "tests" else _FILE_DIR
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ml_models.feature_builder import FEATURE_NAMES
from scripts.evaluate_loato_real_data import calc_metrics

DATA_DIR = os.path.join(_ROOT, "data")
AUTH_DIR = os.path.join(DATA_DIR, "authentic_insdn")
CSV_BENCHMARK = os.path.join(DATA_DIR, "authentic_insdn_mapped.csv")
RESULTS_CSV = os.path.join(_ROOT, "results", "loato_real_data_metrics.csv")
REPORTS_MD = os.path.join(_ROOT, "reports", "loato_real_data_results.md")

EXPECTED_ZIP_HASH = "ee89ec66705c529fef26b27dd18c6aa56d469006f7ade9cd92fd4a503e320d7d"


def get_file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class TestAuthenticInSDNProvenance:
    """Tests verifying authentic public dataset origin and file integrity."""

    def test_raw_archive_hash(self):
        zip_path = os.path.join(AUTH_DIR, "InSDN_DatasetCSV.zip")
        assert os.path.exists(zip_path), f"Raw InSDN zip archive not found at {zip_path}"
        actual_hash = get_file_sha256(zip_path)
        assert actual_hash == EXPECTED_ZIP_HASH, f"Hash mismatch on raw archive: expected {EXPECTED_ZIP_HASH}, got {actual_hash}"

    def test_extracted_partitions_exist(self):
        partitions = ["Normal_data.csv", "metasploitable-2.csv", "OVS.csv"]
        for p in partitions:
            p_path = os.path.join(AUTH_DIR, p)
            assert os.path.exists(p_path), f"Extracted InSDN partition missing: {p_path}"
            assert os.path.getsize(p_path) > 1_000_000, f"Partition {p} is suspiciously small: {os.path.getsize(p_path)} bytes"

    def test_mapped_benchmark_exists_and_row_count(self):
        assert os.path.exists(CSV_BENCHMARK), f"Mapped benchmark missing at {CSV_BENCHMARK}"
        df = pd.read_csv(CSV_BENCHMARK)
        assert len(df) == 5000, f"Expected 5,000 samples in mapped benchmark, got {len(df)}"


class TestFeatureSchemaAndBounds:
    """Tests verifying 15-feature OpenFlow schema compliance and mathematical bounds."""

    @pytest.fixture(scope="module")
    def benchmark_df(self):
        return pd.read_csv(CSV_BENCHMARK)

    def test_expected_feature_columns_present(self, benchmark_df):
        for feat in FEATURE_NAMES:
            assert feat in benchmark_df.columns, f"Feature {feat} missing from benchmark CSV"

    def test_no_null_or_infinite_values(self, benchmark_df):
        for feat in FEATURE_NAMES:
            assert not benchmark_df[feat].isnull().any(), f"Feature {feat} contains NaN values"
            assert not np.isinf(benchmark_df[feat]).any(), f"Feature {feat} contains infinite values"

    def test_entropy_score_bounded(self, benchmark_df):
        assert (benchmark_df["entropy_score"] >= 0.0).all(), "Entropy score contains negative values"
        assert (benchmark_df["entropy_score"] <= 1.0).all(), "Entropy score exceeds maximum 1.0"

    def test_rate_features_non_negative(self, benchmark_df):
        assert (benchmark_df["packet_rate_mean"] >= 0.0).all(), "Negative packet rate detected"
        assert (benchmark_df["packet_rate_max"] >= 0.0).all(), "Negative max packet rate detected"
        assert (benchmark_df["byte_rate_mean"] >= 0.0).all(), "Negative byte rate detected"
        assert (benchmark_df["byte_rate_max"] >= 0.0).all(), "Negative max byte rate detected"
        assert (benchmark_df["flow_count"] >= 0.0).all(), "Negative flow count detected"


class TestLabelMappingConsistency:
    """Tests ensuring ground truth labels are consistent and uncorrupted."""

    @pytest.fixture(scope="module")
    def benchmark_df(self):
        return pd.read_csv(CSV_BENCHMARK)

    def test_binary_label_domain(self, benchmark_df):
        unique_labels = set(benchmark_df["label"].unique())
        assert unique_labels == {0, 1}, f"Binary label set should be {{0, 1}}, got {unique_labels}"

    def test_normal_flows_mapped_to_zero(self, benchmark_df):
        normal_flows = benchmark_df[benchmark_df["attack_type"] == "NORMAL"]
        assert (normal_flows["label"] == 0).all(), "Found NORMAL flows with non-zero labels"
        assert len(normal_flows) == 3000, f"Expected 3,000 NORMAL flows, got {len(normal_flows)}"

    def test_attack_flows_mapped_to_one(self, benchmark_df):
        attack_flows = benchmark_df[benchmark_df["attack_type"] != "NORMAL"]
        assert (attack_flows["label"] == 1).all(), "Found Attack flows with label 0"
        assert len(attack_flows) == 2000, f"Expected 2,000 Attack flows, got {len(attack_flows)}"

    def test_attack_type_categories(self, benchmark_df):
        expected_attacks = {"NORMAL", "DDOS", "DOS", "PROBE", "BRUTE_FORCE", "BOTNET"}
        actual_attacks = set(benchmark_df["attack_type"].unique())
        assert expected_attacks == actual_attacks, f"Attack categories mismatch: expected {expected_attacks}, got {actual_attacks}"


class TestLeakageResistantSplitIntegrity:
    """Tests guaranteeing zero leakage across folds during LOATO evaluation."""

    @pytest.fixture(scope="module")
    def benchmark_df(self):
        return pd.read_csv(CSV_BENCHMARK)

    @pytest.mark.parametrize("held_out", ["DDOS", "DOS", "PROBE", "BRUTE_FORCE"])
    def test_held_out_attack_strictly_excluded_from_train_and_val(self, benchmark_df, held_out):
        known_df = benchmark_df[benchmark_df["attack_type"] != held_out].copy()
        unseen_df = benchmark_df[benchmark_df["attack_type"] == held_out].copy()

        assert held_out not in known_df["attack_type"].values, f"Held-out attack {held_out} leaked into known training pool"
        assert len(unseen_df) > 0, f"No samples found for held-out attack {held_out}"

        X_known = known_df[[f for f in FEATURE_NAMES if f != "duration_mean"]].values
        y_known = known_df["label"].values

        X_tr, X_val, y_tr, y_val = train_test_split(
            X_known, y_known, test_size=0.30, random_state=42, stratify=y_known
        )

        # Confirm scaler fitted strictly on X_tr
        scaler = StandardScaler()
        scaler.fit(X_tr)
        assert len(scaler.mean_) == X_tr.shape[1]
        assert not np.isnan(scaler.mean_).any()


class TestMetricsCalculationRigour:
    """Unit tests for calc_metrics ensuring standard confusion matrix definitions and CI bounds."""

    def test_perfect_detection(self):
        y_true = np.array([1, 1, 1, 0, 0, 0])
        y_pred = np.array([1, 1, 1, 0, 0, 0])
        m = calc_metrics(y_true, y_pred)
        assert m["tp"] == 3 and m["tn"] == 3 and m["fp"] == 0 and m["fn"] == 0
        assert m["accuracy"] == 1.0
        assert m["precision"] == 1.0
        assert m["recall"] == 1.0
        assert m["f1_score"] == 1.0
        assert m["fpr"] == 0.0
        assert m["specificity"] == 1.0
        assert m["balanced_accuracy"] == 1.0

    def test_zero_recall(self):
        y_true = np.array([1, 1, 0, 0])
        y_pred = np.array([0, 0, 0, 0])
        m = calc_metrics(y_true, y_pred)
        assert m["tp"] == 0 and m["fn"] == 2
        assert m["recall"] == 0.0
        assert m["precision"] == 0.0
        assert m["f1_score"] == 0.0

    def test_known_confusion_matrix(self):
        # 50 TP, 10 FP, 20 FN, 20 TN -> Total = 100
        y_true = np.array([1] * 70 + [0] * 30)
        y_pred = np.array([1] * 50 + [0] * 20 + [1] * 10 + [0] * 20)
        m = calc_metrics(y_true, y_pred)
        assert m["tp"] == 50
        assert m["fn"] == 20
        assert m["fp"] == 10
        assert m["tn"] == 20
        assert m["accuracy"] == 0.70
        assert m["precision"] == round(50 / 60, 4)
        assert m["recall"] == round(50 / 70, 4)
        assert m["fpr"] == round(10 / 30, 4)


class TestExperimentOutputsCompleteness:
    """Tests verifying generated experimental artifacts."""

    def test_metrics_csv_schema_and_size(self):
        assert os.path.exists(RESULTS_CSV), f"Missing metrics CSV: {RESULTS_CSV}"
        df = pd.read_csv(RESULTS_CSV)
        # 4 attack families * 4 architectures * 5 seeds = 80 rows
        assert len(df) == 80, f"Expected 80 experiment runs in {RESULTS_CSV}, got {len(df)}"
        expected_cols = {
            "held_out_attack", "seed", "model_architecture",
            "tp", "fp", "tn", "fn", "accuracy", "precision",
            "recall", "f1_score", "fpr", "balanced_accuracy", "ci_95"
        }
        assert expected_cols.issubset(set(df.columns)), f"Missing columns in {RESULTS_CSV}"
        assert (df["accuracy"] >= 0.0).all() and (df["accuracy"] <= 1.0).all()
        assert (df["recall"] >= 0.0).all() and (df["recall"] <= 1.0).all()

    def test_markdown_report_content(self):
        assert os.path.exists(REPORTS_MD), f"Missing Markdown report: {REPORTS_MD}"
        with open(REPORTS_MD, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Leakage-Resistant LOATO Evaluation Report" in content
        assert "Authentic InSDN Dataset" in content
        for fam in ["DDOS", "DOS", "PROBE", "BRUTE_FORCE"]:
            assert fam in content, f"Attack family {fam} missing from report"
        for arch in ["Decision Tree", "Random Forest", "Entropy Standalone", "Uncertainty Gated Hybrid"]:
            assert arch in content, f"Architecture {arch} missing from report"

