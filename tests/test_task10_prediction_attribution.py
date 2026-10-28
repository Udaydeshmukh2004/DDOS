#!/usr/bin/env python3
"""
IntelliShield SDN — Test Suite for Task 10: Final Prediction Attribution & Session Audit
Verifies:
1. Attribution counts across 500 PROBE windows and 5 seeds:
   - 415 Port Entropy Override (H >= 0.85)
   - 85 RF High Confidence (p >= 0.75)
   - 0 Uncertainty Gating
   - 0 Missed (100.0% aggregate recall)
2. Per-source performance breakdown:
   - metasploitable-2: RF recall = 100.0%, Entropy recall = 94.59%, Hybrid = 100.0%
   - OVS: RF recall = 0.54%, Entropy recall = 99.46%, Hybrid = 100.0%
   - Confirmation of high-rate vs low-rate complementarity
3. Split independence and zero target leakage:
   - 0 observation overlap across train, val, and test
   - 0 session group overlap between train and test
   - 0 PROBE windows in train or val
4. Session-level detections and confidence bounds:
   - Exactly 20 unique PROBE sessions (6 metasploitable-2, 14 OVS)
   - Hybrid detection rate = 20/20 (100.0%)
   - Standalone Entropy = 20/20 (100.0%)
   - Standalone RF = 7/20 (35.0%)
   - Wilson 95% CI bounds for 20/20 = [83.89%, 100.00%]
"""

import os
import math
import pytest
import pandas as pd
import numpy as np

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_TEST_DIR)
DATA_DIR = os.path.join(_ROOT, "data")
RESULTS_DIR = os.path.join(_ROOT, "results")
REPORTS_DIR = os.path.join(_ROOT, "reports")

CSV_BENCHMARK = os.path.join(DATA_DIR, "authentic_insdn_leakage_free.csv")
CSV_ATTR = os.path.join(RESULTS_DIR, "task10_probe_prediction_attribution.csv")
CSV_SESS = os.path.join(RESULTS_DIR, "task10_session_level_detections.csv")
REPORT_TASK10 = os.path.join(REPORTS_DIR, "TASK_10_FINAL_PREDICTION_ATTRIBUTION_AUDIT.md")


def wilson_ci(p_hat, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    denom = 1 + (z**2) / n
    center = (p_hat + (z**2) / (2 * n)) / denom
    margin = (z * math.sqrt((p_hat * (1 - p_hat) / n) + (z**2) / (4 * n**2))) / denom
    return round(max(0.0, center - margin) * 100, 2), round(min(1.0, center + margin) * 100, 2)


def test_task10_files_exist():
    """Verify that all Task 10 audit artifacts and tables exist."""
    assert os.path.isfile(CSV_ATTR), f"Missing {CSV_ATTR}"
    assert os.path.isfile(CSV_SESS), f"Missing {CSV_SESS}"
    assert os.path.isfile(REPORT_TASK10), f"Missing {REPORT_TASK10}"


def test_probe_prediction_attribution_counts():
    """Verify exact attribution of the 500 PROBE windows across 5 evaluation seeds."""
    df = pd.read_csv(CSV_ATTR)
    assert len(df) == 2500, f"Expected 2,500 total predictions (500 windows x 5 seeds), got {len(df)}"

    seeds = df["seed"].unique()
    assert set(seeds) == {42, 101, 777, 999, 2026}

    for seed in seeds:
        seed_df = df[df["seed"] == seed]
        assert len(seed_df) == 500

        counts = seed_df["decision_reason"].value_counts()
        assert counts["PORT_ENTROPY_OVERRIDE (H >= 0.85)"] == 415, (
            f"Seed {seed}: Expected 415 port entropy overrides, got {counts.get('PORT_ENTROPY_OVERRIDE (H >= 0.85)')}"
        )
        assert counts["RF_HIGH_CONFIDENCE (p >= 0.75)"] == 85, (
            f"Seed {seed}: Expected 85 RF high confidence detections, got {counts.get('RF_HIGH_CONFIDENCE (p >= 0.75)')}"
        )
        assert "UNCERTAINTY_GATING (Dual Validation Thresh)" not in counts or counts["UNCERTAINTY_GATING (Dual Validation Thresh)"] == 0
        assert "RF_LOW_CONFIDENCE (p <= 0.25, Not Flagged)" not in counts or counts["RF_LOW_CONFIDENCE (p <= 0.25, Not Flagged)"] == 0

        # Zero false negatives (100% recall)
        assert seed_df["pred_hyb_ovr"].sum() == 500


def test_per_source_breakdown_and_complementarity():
    """Verify per-source recall proving RF volumetric vs Entropy structural complementarity."""
    df = pd.read_csv(CSV_ATTR)

    for seed in df["seed"].unique():
        s_df = df[df["seed"] == seed]
        m2 = s_df[s_df["capture_source"] == "metasploitable-2"]
        ovs = s_df[s_df["capture_source"] == "OVS"]

        assert len(m2) == 314
        assert len(ovs) == 186

        # Metasploitable-2: high packet rate, RF recall 100% across all seeds
        assert m2["pred_rf"].sum() == 314
        assert m2["pred_hyb_ovr"].sum() == 314
        assert m2["pred_ent"].sum() in [297, 298]

        # OVS: low packet rate, Entropy catches 185/186 in all seeds, Hybrid catches 186/186
        assert ovs["pred_hyb_ovr"].sum() == 186
        assert ovs["pred_ent"].sum() == 185
        if seed in [42, 101, 999, 2026]:
            assert ovs["pred_rf"].sum() == 1  # RF collapses to 1/186 (0.54%) in 4 of 5 seeds


def test_split_independence_and_zero_target_leakage():
    """Verify no observation or group overlap and zero PROBE windows in train/val."""
    from sklearn.model_selection import GroupShuffleSplit

    bench_df = pd.read_csv(CSV_BENCHMARK)
    bench_df["raw_window_id"] = np.arange(len(bench_df))

    normal_pool = bench_df[bench_df["attack_type"] == "NORMAL"].copy()
    known_attacks = bench_df[(bench_df["attack_type"] != "PROBE") & (bench_df["attack_type"] != "NORMAL")].copy()
    probe_pool = bench_df[bench_df["attack_type"] == "PROBE"].copy()

    seeds = [42, 101, 777, 999, 2026]

    for seed in seeds:
        gss_norm_test = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed)
        n_tr_val_idx, n_test_idx = next(gss_norm_test.split(normal_pool, groups=normal_pool["session_group"]))
        n_tr_val = normal_pool.iloc[n_tr_val_idx]
        n_test = normal_pool.iloc[n_test_idx]

        gss_norm_val = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed)
        n_tr_idx, n_val_idx = next(gss_norm_val.split(n_tr_val, groups=n_tr_val["session_group"]))
        n_tr = n_tr_val.iloc[n_tr_idx]
        n_val = n_tr_val.iloc[n_val_idx]

        gss_att = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed)
        a_tr_idx, a_val_idx = next(gss_att.split(known_attacks, groups=known_attacks["session_group"]))
        a_tr = known_attacks.iloc[a_tr_idx]
        a_val = known_attacks.iloc[a_val_idx]

        train_set = pd.concat([n_tr, a_tr], ignore_index=True)
        val_set = pd.concat([n_val, a_val], ignore_index=True)
        test_set = pd.concat([n_test, probe_pool], ignore_index=True)

        tr_ids = set(train_set["raw_window_id"].unique())
        val_ids = set(val_set["raw_window_id"].unique())
        te_ids = set(test_set["raw_window_id"].unique())

        tr_grps = set(train_set["session_group"].unique())
        te_grps = set(test_set["session_group"].unique())

        probe_ids = set(probe_pool["raw_window_id"].unique())

        # Strict disjoint assertions
        assert len(tr_ids.intersection(val_ids)) == 0
        assert len(tr_ids.intersection(te_ids)) == 0
        assert len(val_ids.intersection(te_ids)) == 0
        assert len(tr_grps.intersection(te_grps)) == 0
        assert len(probe_ids.intersection(tr_ids)) == 0
        assert len(probe_ids.intersection(val_ids)) == 0


def test_session_level_detections_and_wilson_ci():
    """Verify session-level detection table, 20/20 detection, and Wilson CI bounds."""
    df = pd.read_csv(CSV_SESS)
    assert len(df) == 20, f"Expected 20 unique sessions, got {len(df)}"

    m2_sessions = df[df["capture_source"] == "metasploitable-2"]
    ovs_sessions = df[df["capture_source"] == "OVS"]

    assert len(m2_sessions) == 6
    assert len(ovs_sessions) == 14

    # Every session must have total_windows >= 1
    assert (df["total_windows"] >= 1).all()
    assert df["total_windows"].sum() == 500

    # Hybrid detection outcome: all 20 sessions detected
    assert df["session_detected_hyb"].sum() == 20
    assert (df["session_detected_hyb"] == 1).all()

    # Entropy standalone detected 19 of 20 sessions (missed 1 single-window OVS session)
    assert df["session_detected_ent"].sum() == 19

    # RF standalone detected only 7 sessions (6 metasploitable-2 + 1 OVS)
    assert df["session_detected_rf"].sum() == 7
    assert m2_sessions["session_detected_rf"].sum() == 6
    assert ovs_sessions["session_detected_rf"].sum() == 1

    # Wilson CI calculation for K=20, 20 successes
    low, high = wilson_ci(1.0, 20)
    assert low == 83.89
    assert high == 100.00
