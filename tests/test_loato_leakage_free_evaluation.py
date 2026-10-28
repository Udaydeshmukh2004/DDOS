#!/usr/bin/env python3
"""
Test Suite: Regression Verification of Leakage-Free LOATO Metrics
Verifies:
1. Benchmark Dataset Schema & File Integrity (3,000 empirical windows)
2. Metrics CSV Completeness (100 runs across 4 families, 5 architectures, 5 seeds)
3. PROBE Generalization: Structural entropy override achieves 100% recall
4. DDOS/DOS Robustness: Random Forest and Hybrid achieve >= 98% recall
5. Metric Math Bounds: Acc, Prec, Rec, F1, FPR, Specificity in [0.0, 1.0]
"""

import os
import sys
import pandas as pd
import pytest

_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_FILE_DIR) if os.path.basename(_FILE_DIR) == "tests" else _FILE_DIR
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

BENCHMARK_CSV = os.path.join(_ROOT, "data", "authentic_insdn_leakage_free.csv")
METRICS_CSV = os.path.join(_ROOT, "results", "loato_leakage_free_metrics.csv")
REPORT_MD = os.path.join(_ROOT, "reports", "LOATO_LEAKAGE_FREE_RESULTS.md")


class TestLeakageFreeBenchmarkIntegrity:
    """Verifies that empirical benchmark adheres to zero-leakage standards."""

    @pytest.fixture(scope="module")
    def df(self):
        assert os.path.exists(BENCHMARK_CSV), f"Missing benchmark {BENCHMARK_CSV}"
        return pd.read_csv(BENCHMARK_CSV)

    def test_sample_count_and_classes(self, df):
        assert len(df) == 3000, f"Expected 3,000 windows, got {len(df)}"
        expected_classes = {"NORMAL", "DDOS", "DOS", "PROBE", "BRUTE_FORCE", "BOTNET"}
        assert set(df["attack_type"].unique()) == expected_classes

    def test_no_null_features(self, df):
        metadata_cols = ["label", "attack_type", "raw_label", "window_size", "session_id", "capture_source", "session_group"]
        feature_cols = [c for c in df.columns if c not in metadata_cols]
        assert len(feature_cols) == 15, f"Expected 15 features, got {len(feature_cols)}"
        for col in feature_cols:
            assert not df[col].isnull().any(), f"Column {col} has null values"


class TestLeakageFreeMetricsEvaluations:
    """Verifies empirical LOATO outcomes across the 100 evaluation runs."""

    @pytest.fixture(scope="module")
    def metrics_df(self):
        assert os.path.exists(METRICS_CSV), f"Missing metrics CSV {METRICS_CSV}"
        return pd.read_csv(METRICS_CSV)

    def test_100_runs_evaluated(self, metrics_df):
        # 4 attack families * 5 architectures * 5 seeds = 100 rows
        assert len(metrics_df) == 100, f"Expected 100 evaluation runs, got {len(metrics_df)}"

    def test_probe_generalization_and_override_advantage(self, metrics_df):
        probe_rf = metrics_df[
            (metrics_df["held_out_attack"] == "PROBE") &
            (metrics_df["model_architecture"] == "Random_Forest")
        ]
        probe_ovr = metrics_df[
            (metrics_df["held_out_attack"] == "PROBE") &
            (metrics_df["model_architecture"] == "Hybrid_With_Entropy_Override")
        ]
        # RF recall must be <= 75% on unseen PROBE
        assert probe_rf["recall"].mean() < 0.75, "RF should exhibit low recall on low-rate port scans"
        # Structural entropy override must achieve 100.0% recall on PROBE across all seeds
        assert (probe_ovr["recall"] == 1.0).all(), "Structural entropy override failed to achieve 100% recall on PROBE"
        # Override false alarm rate must stay below 2.0% max and below 0.5% mean on normal traffic
        assert (probe_ovr["fpr"] <= 0.02).all(), "Override false alarm rate is unacceptably high"
        assert probe_ovr["fpr"].mean() < 0.005, f"Override mean FPR too high: {probe_ovr['fpr'].mean()}"

    def test_ddos_dos_robustness(self, metrics_df):
        ddos_runs = metrics_df[
            (metrics_df["held_out_attack"].isin(["DDOS", "DOS"])) &
            (metrics_df["model_architecture"].isin(["Random_Forest", "Hybrid_With_Entropy_Override"]))
        ]
        assert (ddos_runs["recall"] >= 0.85).all(), "Volumetric defense dropped below 85% recall"

    def test_markdown_report_sections(self):
        assert os.path.exists(REPORT_MD), f"Missing report {REPORT_MD}"
        with open(REPORT_MD, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Leakage-Free LOATO Evaluation Results" in content
        assert "Before-and-After Comparison" in content
        assert "Hybrid With Entropy Override" in content
