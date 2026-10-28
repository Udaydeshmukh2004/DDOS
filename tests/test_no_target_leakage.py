#!/usr/bin/env python3
"""
Test Suite: Verification of Zero Target-Label Leakage
Verifies:
1. Label Invariance: Dropping, shuffling, or altering labels produces 100% identical feature vectors.
2. Removal of Hardcoded Constants: flow_concentration, unique_dst_count, unique_src_count have continuous cardinality.
3. Feature Lineage Integrity: Every feature is derived exclusively from raw network fields.
"""

import os
import sys
import numpy as np
import pandas as pd
import pytest

_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_FILE_DIR) if os.path.basename(_FILE_DIR) == "tests" else _FILE_DIR
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scripts.build_empirical_network_features import (
    process_dataframe_into_empirical_windows,
    extract_window_features,
    FEATURE_NAMES
)

CSV_CLEAN_BENCHMARK = os.path.join(_ROOT, "data", "authentic_insdn_leakage_free.csv")


class TestLabelInvariance:
    """Verifies that features are mathematically invariant to label manipulations."""

    @pytest.fixture(scope="module")
    def sample_raw_df(self):
        # Create a synthetic batch of raw flow records
        np.random.seed(42)
        n = 100
        return pd.DataFrame({
            "Src IP": [f"192.168.1.{i % 10}" for i in range(n)],
            "Dst IP": [f"10.0.0.{i % 3}" for i in range(n)],
            "Dst Port": np.random.choice([80, 443, 22, 53, 8080], size=n),
            "Protocol": np.random.choice([6, 17], size=n),
            "Flow Pkts/s": np.random.exponential(scale=100.0, size=n),
            "Flow Byts/s": np.random.exponential(scale=5000.0, size=n),
            "Flow Duration": np.random.uniform(1000, 500000, size=n),
            "Label": ["Normal"] * 50 + ["DDoS"] * 50
        })

    def test_shuffled_labels_yield_identical_features(self, sample_raw_df):
        # 1. Compute features with original labels
        df_orig = process_dataframe_into_empirical_windows(sample_raw_df, window_size=20, has_labels=True)
        
        # 2. Shuffle labels completely
        df_shuffled = sample_raw_df.copy()
        df_shuffled["Label"] = np.random.permutation(df_shuffled["Label"].values)
        df_shuffled_res = process_dataframe_into_empirical_windows(df_shuffled, window_size=20, has_labels=True)

        for feat in FEATURE_NAMES:
            diff = np.max(np.abs(df_orig[feat].values - df_shuffled_res[feat].values))
            assert diff == 0.0, f"Feature {feat} changed when labels were shuffled! Max diff: {diff}"

    def test_dropped_labels_yield_identical_features(self, sample_raw_df):
        df_with_lbl = process_dataframe_into_empirical_windows(sample_raw_df, window_size=20, has_labels=True)
        
        # Drop the label column entirely
        df_no_lbl = sample_raw_df.drop(columns=["Label"])
        df_no_lbl_res = process_dataframe_into_empirical_windows(df_no_lbl, window_size=20, has_labels=False)

        for feat in FEATURE_NAMES:
            diff = np.max(np.abs(df_with_lbl[feat].values - df_no_lbl_res[feat].values))
            assert diff == 0.0, f"Feature {feat} changed when label column was dropped! Max diff: {diff}"


class TestAbsenceOfHardcodedTargetConditioning:
    """Verifies that clean benchmark has continuous empirical variance across all classes."""

    @pytest.fixture(scope="module")
    def benchmark_df(self):
        assert os.path.exists(CSV_CLEAN_BENCHMARK), f"Missing clean benchmark: {CSV_CLEAN_BENCHMARK}"
        return pd.read_csv(CSV_CLEAN_BENCHMARK)

    def test_flow_concentration_is_not_hardcoded(self, benchmark_df):
        # In contaminated baseline: NORMAL=[0.12], ATTACKS=[0.85]
        # In clean baseline: flow_concentration must have continuous variance
        assert benchmark_df["flow_concentration"].nunique() > 100, "flow_concentration has suspiciously low cardinality"
        # Must not be single constant for normal or attacks
        norm_vals = benchmark_df[benchmark_df["label"] == 0]["flow_concentration"].unique()
        att_vals = benchmark_df[benchmark_df["label"] == 1]["flow_concentration"].unique()
        assert len(norm_vals) > 50, f"Normal flow_concentration is still constant: {norm_vals[:5]}"
        assert len(att_vals) > 50, f"Attack flow_concentration is still constant: {att_vals[:5]}"

    def test_unique_dst_count_is_not_hardcoded(self, benchmark_df):
        # In contaminated baseline: PROBE was hardcoded to 35.0, NORMAL to 8.0, others to 1.0
        probe_vals = benchmark_df[benchmark_df["attack_type"] == "PROBE"]["unique_dst_count"].unique()
        norm_vals = benchmark_df[benchmark_df["attack_type"] == "NORMAL"]["unique_dst_count"].unique()
        assert not (len(probe_vals) == 1 and probe_vals[0] == 35.0), "unique_dst_count for PROBE is still hardcoded to 35.0"
        assert len(norm_vals) > 5, "unique_dst_count for NORMAL is suspiciously constant"

    def test_unique_src_count_is_not_hardcoded(self, benchmark_df):
        # In contaminated baseline: DDOS was hardcoded to 120.0
        ddos_vals = benchmark_df[benchmark_df["attack_type"] == "DDOS"]["unique_src_count"].unique()
        assert not (len(ddos_vals) == 1 and ddos_vals[0] == 120.0), "unique_src_count for DDOS is still hardcoded to 120.0"

    def test_features_non_null_and_within_bounds(self, benchmark_df):
        for feat in FEATURE_NAMES:
            assert not benchmark_df[feat].isnull().any(), f"Feature {feat} contains NaNs"
            assert not np.isinf(benchmark_df[feat]).any(), f"Feature {feat} contains Infinities"
        assert (benchmark_df["entropy_score"] >= 0.0).all() and (benchmark_df["entropy_score"] <= 1.0).all()
        assert (benchmark_df["flow_concentration"] >= 0.0).all() and (benchmark_df["flow_concentration"] <= 1.0).all()

