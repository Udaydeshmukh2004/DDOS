#!/usr/bin/env python3
"""
IntelliShield SDN — Test Suite for Task 13: Final Prediction Attribution and Generalization Check
Validates:
1. Artifact existence: task13_final_probe_attribution.csv, TASK_13_FINAL_ATTRIBUTION_AND_GENERALIZATION.md.
2. Exact resolution of the 18 DT-only windows (17 metasploitable-2 + 1 OVS).
3. Exact set union: 297 both + 17 DT-m2 + 1 DT-ovs + 185 Ent-ovs + 0 neither = 500.
4. Identification and scoring of Window ID 1677 (the single OVS DT-only detection).
5. Capture units accounting: 6 metasploitable-2 sessions (314 windows), 14 OVS sessions (186 windows).
"""

import os
import pytest
import pandas as pd
import numpy as np

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_TEST_DIR)
RESULTS_DIR = os.path.join(_ROOT, "results")
REPORTS_DIR = os.path.join(_ROOT, "reports")

ATTR_CSV = os.path.join(RESULTS_DIR, "task13_final_probe_attribution.csv")
REPORT_MD = os.path.join(REPORTS_DIR, "TASK_13_FINAL_ATTRIBUTION_AND_GENERALIZATION.md")


def test_task13_artifacts_exist():
    """Verify that Task 13 report and CSV exist."""
    assert os.path.isfile(ATTR_CSV), f"Missing {ATTR_CSV}"
    assert os.path.isfile(REPORT_MD), f"Missing {REPORT_MD}"


def test_attribution_discrepancy_resolved():
    """Verify exact counts resolving the Task 12 attribution discrepancy."""
    df = pd.read_csv(ATTR_CSV)
    assert len(df) == 500

    counts = df["attribution_category"].value_counts().to_dict()

    assert counts["BOTH_DT_AND_ENTROPY"] == 297
    assert counts["ENTROPY_ONLY_OVS"] == 185
    assert counts["DT_ONLY_METASPLOITABLE2"] == 17
    assert counts["DT_ONLY_OVS"] == 1
    assert "NEITHER" not in counts or counts["NEITHER"] == 0

    # Total DT-only detections
    dt_only_total = counts["DT_ONLY_METASPLOITABLE2"] + counts["DT_ONLY_OVS"]
    assert dt_only_total == 18

    # Total union
    total_union = counts["BOTH_DT_AND_ENTROPY"] + dt_only_total + counts["ENTROPY_ONLY_OVS"]
    assert total_union == 500


def test_window_1677_ovs_dt_only():
    """Verify the single OVS window detected by Decision Tree and missed by Entropy."""
    df = pd.read_csv(ATTR_CSV)
    w1677 = df[df["raw_window_id"] == 1677]
    assert len(w1677) == 1

    row = w1677.iloc[0]
    assert row["capture_source"] == "OVS"
    assert row["session_group"] == "OVS_26/12/2019 02:32:34 PM"
    assert round(row["port_entropy"], 4) == 0.6135
    assert row["pred_dt"] == 1
    assert row["pred_ent_val"] == 0
    assert row["pred_hyb_dt"] == 1
    assert row["reason_hyb_dt"] == "DT_HIGH_CONFIDENCE (p >= 0.75)"
    assert row["attribution_category"] == "DT_ONLY_OVS"


def test_capture_units_and_sessions():
    """Verify the 20 discrete capture sessions and their window distribution."""
    df = pd.read_csv(ATTR_CSV)
    sess_counts = df.groupby(["capture_source", "session_group"]).size().reset_index(name="win_count")

    m2_sess = sess_counts[sess_counts["capture_source"] == "metasploitable-2"]
    ovs_sess = sess_counts[sess_counts["capture_source"] == "OVS"]

    assert len(m2_sess) == 6
    assert len(ovs_sess) == 14
    assert len(sess_counts) == 20

    assert m2_sess["win_count"].sum() == 314
    assert ovs_sess["win_count"].sum() == 186
    assert sess_counts["win_count"].sum() == 500

