#!/usr/bin/env python3
"""
IntelliShield SDN — Automated Tests for Task 9 Independence and Statistical Integrity Audit
Validates:
1. Exact unique vs repeated observation counts (500 unique attack windows repeated 5 times = 2500 rows).
2. Exactly 20 unique capture sessions for PROBE attacks.
3. Disjoint test partition sizes summing to 3,776 total rows.
4. Presence of formal pseudo-replication disclosure in the audit report.
"""

import os
import math
import pytest
import numpy as np
import pandas as pd

_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_FILE_DIR) if os.path.basename(_FILE_DIR) == "tests" else _FILE_DIR

CSV_BENCHMARK = os.path.join(_ROOT, "data", "authentic_insdn_leakage_free.csv")
PREDS_CSV = os.path.join(_ROOT, "results", "task6_per_observation_predictions.csv")
TASK9_CSV = os.path.join(_ROOT, "results", "task9_unique_sample_counts.csv")
TASK9_REP = os.path.join(_ROOT, "reports", "TASK_9_INDEPENDENCE_AUDIT.md")

class TestTask9UniqueSampleCounts:
    def test_unique_sample_counts_csv_matches(self):
        assert os.path.exists(TASK9_CSV), f"Missing {TASK9_CSV}"
        df = pd.read_csv(TASK9_CSV)
        cat_map = dict(zip(df["Category"], df["Count"]))
        
        assert cat_map["Total Prediction Rows (All 5 Seeds)"] == 3776
        assert cat_map["Attack Prediction Rows"] == 2500
        assert cat_map["Unique Attack Windows (PROBE)"] == 500
        assert cat_map["Unique Attack Sessions (PROBE)"] == 20
        assert cat_map["Attack Repetitions per Window"] == 5.0
        assert cat_map["Normal Prediction Rows"] == 1276
        assert cat_map["Unique Normal Windows"] == 901
        assert cat_map["Unique Normal Sessions"] == 247

    def test_saved_predictions_per_seed_counts(self):
        assert os.path.exists(PREDS_CSV), f"Missing {PREDS_CSV}"
        df = pd.read_csv(PREDS_CSV)
        assert len(df) == 3776
        
        # 5 seeds with 500 positive attacks each
        pos_df = df[df["y_true"] == 1]
        assert len(pos_df) == 2500
        assert (pos_df.groupby("seed").size() == 500).all()
        
        # Negatives
        neg_df = df[df["y_true"] == 0]
        assert len(neg_df) == 1276

    def test_task9_report_contains_required_sections_and_verdict(self):
        assert os.path.exists(TASK9_REP), f"Missing {TASK9_REP}"
        with open(TASK9_REP, "r", encoding="utf-8") as f:
            content = f.read()
        assert "READY FOR MANUSCRIPT UPDATE WITH EXPLICIT LIMITATIONS" in content
        assert "Pseudo-Replication Eliminated" in content
        assert "Primary LOATO versus Source-Held-Out" in content

