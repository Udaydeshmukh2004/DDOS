#!/usr/bin/env python3
"""
IntelliShield SDN — Automated Tests for Task 8 Scientific Consistency
Validates:
1. Exact mathematical lower bound of port dispersion entropy (k >= 20 required for H >= 0.85).
2. Proof that k <= 19 cannot reach H >= 0.85 under any distribution of 50 flows.
3. Bidirectional PROBE dataset split integrity and disjointness.
4. Reconciliation of all 3,776 saved predictions with confusion matrix denominators.
"""

import os
import math
import pytest
import numpy as np
import pandas as pd

_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_FILE_DIR) if os.path.basename(_FILE_DIR) == "tests" else _FILE_DIR

BENCH_CSV = os.path.join(_ROOT, "data", "authentic_insdn_leakage_free.csv")
PREDS_CSV = os.path.join(_ROOT, "results", "task6_per_observation_predictions.csv")
TASK8_CSV = os.path.join(_ROOT, "results", "task8_bidirectional_probe_metrics.csv")
TASK8_REP = os.path.join(_ROOT, "reports", "TASK_8_SCIENTIFIC_INCONSISTENCY_RESOLUTION.md")

class TestMathematicalEntropyBound:
    def test_continuous_entropy_bound(self):
        # Formula: H_norm = log2(k) / 5.0
        # For k=19: log2(19) / 5.0 < 0.85
        assert math.log2(19) / 5.0 < 0.85
        # For k=20: log2(20) / 5.0 >= 0.85
        assert math.log2(20) / 5.0 >= 0.85
        
    def test_discrete_integer_partitions_of_50_flows(self):
        def calc_h(counts):
            probs = np.array(counts, dtype=float) / 50.0
            h_raw = -np.sum(probs * np.log2(probs + 1e-12))
            return h_raw / 5.0
            
        # Max integer entropy for k=19 (12x3 + 7x2 = 50)
        c19 = [3]*12 + [2]*7
        assert sum(c19) == 50
        assert len(c19) == 19
        assert calc_h(c19) < 0.85
        
        # Max integer entropy for k=20 (10x3 + 10x2 = 50)
        c20 = [3]*10 + [2]*10
        assert sum(c20) == 50
        assert len(c20) == 20
        assert calc_h(c20) >= 0.85
        
    def test_k19_suboptimal_distributions_strictly_less_than_085(self):
        # Any other partition of 50 into 19 categories has even lower entropy
        c19_skewed = [11] + [2]*15 + [3]*3
        assert sum(c19_skewed) == 50
        assert len(c19_skewed) == 19
        probs = np.array(c19_skewed, dtype=float) / 50.0
        h_skewed = -np.sum(probs * np.log2(probs + 1e-12)) / 5.0
        assert h_skewed < 0.85

class TestTask8PredictionsAndMetricsIntegrity:
    def test_saved_predictions_reconciliation(self):
        assert os.path.exists(PREDS_CSV)
        df = pd.read_csv(PREDS_CSV)
        assert len(df) == 3776
        
        # 5 seeds with 500 positive attacks each
        pos_df = df[df["y_true"] == 1]
        assert len(pos_df) == 2500
        assert (pos_df.groupby("seed").size() == 500).all()
        
        # Negative normal test counts
        neg_df = df[df["y_true"] == 0]
        assert len(neg_df) == 1276
        assert len(neg_df) + len(pos_df) == 3776

    def test_task8_bidirectional_csv_exists_and_reconciled(self):
        assert os.path.exists(TASK8_CSV)
        df = pd.read_csv(TASK8_CSV)
        assert len(df) > 0
        # Check Direction A (meta-2 -> OVS): RF recall is 45.70%, Entropy recall is 99.46%
        dirA = df[(df["direction"] == "meta2_to_OVS") & (df["test_normal_variant"] == "fixed_209")]
        rf_rec = dirA[dirA["model"] == "Random Forest"]["recall"].values[0]
        ent_rec = dirA[dirA["model"] == "Port Entropy (A Priori 0.85)"]["recall"].values[0]
        assert round(rf_rec * 100, 2) == 45.70
        assert round(ent_rec * 100, 2) == 99.46

    def test_task8_report_exists_and_contains_formal_withdrawal(self):
        assert os.path.exists(TASK8_REP)
        with open(TASK8_REP, "r", encoding="utf-8") as f:
            content = f.read()
        assert "READY FOR MANUSCRIPT UPDATE WITH EXPLICIT LIMITATIONS" in content
        assert "20 distinct destination ports" in content
        assert "withdrawn" in content.lower()

