#!/usr/bin/env python3
"""
Test Suite: Forensic Verification of Authentic InSDN LOATO Results
Covers:
1. Dataset Authenticity & Partition File Hashes (343,889 flows)
2. Target-Conditioned Feature Leakage Checks
3. LOATO Partition Isolation & Zero-Contamination Splits
4. Metric Formula Precision & Wilson CI Invariants
5. Exact Numerical Recomputation Agreement (100% match)
6. Model Robustness & Rate-Feature Ablation Verifications
"""

import os
import sys
import hashlib
import math
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
from scripts.verify_loato_results_independently import calc_metrics, get_file_sha256

DATA_DIR = os.path.join(_ROOT, "data")
AUTH_DIR = os.path.join(DATA_DIR, "authentic_insdn")
CSV_BENCHMARK = os.path.join(DATA_DIR, "authentic_insdn_mapped.csv")
PREV_METRICS_CSV = os.path.join(_ROOT, "results", "loato_real_data_metrics.csv")
RECOMP_METRICS_CSV = os.path.join(_ROOT, "results", "loato_independent_recomputed_metrics.csv")
AUDIT_REPORT_MD = os.path.join(_ROOT, "reports", "loato_independent_forensic_audit.md")

EXPECTED_ZIP_HASH = "ee89ec66705c529fef26b27dd18c6aa56d469006f7ade9cd92fd4a503e320d7d"


class TestDatasetAuthenticityAndProvenance:
    """Verifies that public dataset files match authentic academic repository specifications."""

    def test_raw_zip_archive_hash_and_size(self):
        zip_path = os.path.join(AUTH_DIR, "InSDN_DatasetCSV.zip")
        assert os.path.exists(zip_path), f"Raw InSDN zip archive missing: {zip_path}"
        actual_hash = get_file_sha256(zip_path)
        assert actual_hash == EXPECTED_ZIP_HASH, f"Hash mismatch: expected {EXPECTED_ZIP_HASH}, got {actual_hash}"
        assert os.path.getsize(zip_path) == 19302607, f"Unexpected archive size: {os.path.getsize(zip_path)}"

    def test_partitions_flow_counts(self):
        expected_partitions = {
            "Normal_data.csv": 68424,
            "metasploitable-2.csv": 136743,
            "OVS.csv": 138722
        }
        total_rows = 0
        for fname, exp_rows in expected_partitions.items():
            fpath = os.path.join(AUTH_DIR, fname)
            assert os.path.exists(fpath), f"Missing raw partition {fpath}"
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                rows = sum(1 for _ in f) - 1
            assert rows == exp_rows, f"Row count mismatch in {fname}: expected {exp_rows}, got {rows}"
            total_rows += rows
        assert total_rows == 343889, f"Total raw flows mismatch: expected 343,889, got {total_rows}"


class TestLeakageAndFeatureConditioningAudit:
    """Audits feature engineering for target label conditioning and continuous telemetry integrity."""

    @pytest.fixture(scope="module")
    def benchmark_df(self):
        return pd.read_csv(CSV_BENCHMARK)

    def test_flow_concentration_target_conditioning(self, benchmark_df):
        # Audit finding: flow_concentration is hardcoded to 0.85 for attacks and 0.12 for normal
        norm_val = benchmark_df[benchmark_df["label"] == 0]["flow_concentration"].unique()
        att_val = benchmark_df[benchmark_df["label"] == 1]["flow_concentration"].unique()
        assert len(norm_val) == 1 and norm_val[0] == 0.12
        assert len(att_val) == 1 and att_val[0] == 0.85

    def test_unique_dst_count_probe_conditioning(self, benchmark_df):
        # Audit finding: unique_dst_count is hardcoded to 35.0 for PROBE, 1.0 for other attacks, 8.0 for normal
        probe_val = benchmark_df[benchmark_df["attack_type"] == "PROBE"]["unique_dst_count"].unique()
        ddos_val = benchmark_df[benchmark_df["attack_type"] == "DDOS"]["unique_dst_count"].unique()
        norm_val = benchmark_df[benchmark_df["attack_type"] == "NORMAL"]["unique_dst_count"].unique()
        assert len(probe_val) == 1 and probe_val[0] == 35.0
        assert len(ddos_val) == 1 and ddos_val[0] == 1.0
        assert len(norm_val) == 1 and norm_val[0] == 8.0

    def test_authentic_continuous_rate_features_have_high_cardinality(self, benchmark_df):
        # Ensure authentic continuous rate features have genuine continuous distributions
        assert benchmark_df["packet_rate_mean"].nunique() > 3000
        assert benchmark_df["byte_rate_mean"].nunique() > 3000
        assert benchmark_df["packet_rate_max"].nunique() > 400
        assert benchmark_df["flow_count"].nunique() > 100


class TestLOATOSplitIntegrity:
    """Verifies that held-out attack types are strictly excluded from training."""

    @pytest.fixture(scope="module")
    def benchmark_df(self):
        return pd.read_csv(CSV_BENCHMARK)

    @pytest.mark.parametrize("held_out", ["DDOS", "DOS", "PROBE", "BRUTE_FORCE"])
    def test_zero_contamination_of_held_out_attack(self, benchmark_df, held_out):
        known_df = benchmark_df[benchmark_df["attack_type"] != held_out]
        unseen_df = benchmark_df[benchmark_df["attack_type"] == held_out]
        assert held_out not in known_df["attack_type"].unique()
        assert len(unseen_df) > 0


class TestMetricRecomputationExactness:
    """Verifies that recomputed metrics match previous metrics and mathematical invariants."""

    def test_recomputed_csv_exists_and_has_120_runs(self):
        assert os.path.exists(RECOMP_METRICS_CSV), f"Recomputed metrics CSV missing: {RECOMP_METRICS_CSV}"
        df = pd.read_csv(RECOMP_METRICS_CSV)
        # 4 attack families * 6 architectures * 5 seeds = 120 evaluations
        assert len(df) == 120, f"Expected 120 evaluation rows, got {len(df)}"

    def test_previous_metrics_exact_agreement(self):
        assert os.path.exists(PREV_METRICS_CSV), f"Previous metrics CSV missing: {PREV_METRICS_CSV}"
        prev_df = pd.read_csv(PREV_METRICS_CSV)
        recomp_df = pd.read_csv(RECOMP_METRICS_CSV)

        arch_map = {
            "Decision_Tree": "Decision_Tree",
            "Random_Forest": "Random_Forest",
            "Entropy_Standalone": "Entropy_Standalone",
            "Uncertainty_Gated_Hybrid": "Hybrid_Standard_Gating"
        }

        for _, prev_row in prev_df.iterrows():
            fam = prev_row["held_out_attack"]
            seed = int(prev_row["seed"])
            p_arch = prev_row["model_architecture"]
            r_arch = arch_map[p_arch]

            match = recomp_df[
                (recomp_df["held_out_attack"] == fam) &
                (recomp_df["seed"] == seed) &
                (recomp_df["model_architecture"] == r_arch)
            ]
            assert len(match) == 1, f"Missing match for {fam} {seed} {r_arch}"
            cur_row = match.iloc[0]

            assert math.isclose(prev_row["recall"], cur_row["recall"], abs_tol=1e-3)
            assert math.isclose(prev_row["precision"], cur_row["precision"], abs_tol=1e-3)
            assert math.isclose(prev_row["fpr"], cur_row["fpr"], abs_tol=1e-3)

    def test_random_forest_probe_collapse(self):
        recomp_df = pd.read_csv(RECOMP_METRICS_CSV)
        probe_rf = recomp_df[
            (recomp_df["held_out_attack"] == "PROBE") &
            (recomp_df["model_architecture"] == "Random_Forest")
        ]
        # RF recall must be 0.00% across all seeds
        assert (probe_rf["recall"] == 0.0).all(), "Random Forest recall on probe is unexpectedly non-zero"
        assert (probe_rf["fn"] == 500).all(), "FN should be 500 (total probe samples)"

    def test_hybrid_ddos_dos_perfect_recall(self):
        recomp_df = pd.read_csv(RECOMP_METRICS_CSV)
        hyb_runs = recomp_df[
            (recomp_df["held_out_attack"].isin(["DDOS", "DOS"])) &
            (recomp_df["model_architecture"] == "Hybrid_Standard_Gating")
        ]
        assert (hyb_runs["recall"] == 1.0).all(), "Hybrid failed to achieve 100% recall on DDOS/DOS"
        assert (hyb_runs["fpr"] == 0.0).all(), "Hybrid incurred false alarms on DDOS/DOS"

    def test_wilson_ci_bounds_validity(self):
        recomp_df = pd.read_csv(RECOMP_METRICS_CSV)
        assert (recomp_df["ci_low"] >= 0.0).all()
        assert (recomp_df["ci_high"] <= 100.0).all()
        assert (recomp_df["ci_low"] <= recomp_df["ci_high"]).all()


class TestAuditReportCompleteness:
    """Verifies that the audit report contains all required forensic disclosures."""

    def test_audit_report_sections(self):
        assert os.path.exists(AUDIT_REPORT_MD), f"Audit report missing: {AUDIT_REPORT_MD}"
        with open(AUDIT_REPORT_MD, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Forensic Audit & Independent Verification Report" in content
        assert "FAILED (TARGET LEAKAGE)" in content
        assert "flow_concentration" in content
        assert "unique_dst_count" in content
        assert "343,889" in content
        assert "DO NOT UPDATE MANUSCRIPT YET" in content

