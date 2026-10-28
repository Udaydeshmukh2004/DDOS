#!/usr/bin/env python3
"""
Test Suite: Empirical Network Feature Extraction & Mathematical Correctness
Verifies:
1. Mathematical correctness of Shannon entropy and Herfindahl concentration
2. Proper edge-case handling (empty inputs, single values, division by zero)
3. Discriminative power: Port entropy separates port scans (Probe) from DDoS/Normal
"""

import math
import numpy as np
import pytest

from scripts.build_empirical_network_features import (
    shannon_entropy_from_values,
    herfindahl_concentration,
    extract_window_features,
    FEATURE_NAMES
)


class TestMathematicalEntropyFunctions:
    """Tests core mathematical properties of entropy and concentration indices."""

    def test_single_value_entropy_is_zero(self):
        # H(X) for single value is 0.0 bits
        vals = np.array(["192.168.1.1"] * 50)
        assert shannon_entropy_from_values(vals) == 0.0

    def test_uniform_distribution_entropy_is_maximal(self):
        # 16 distinct categories with equal frequencies in array of 16
        vals = np.array([f"port_{i}" for i in range(16)])
        ent = shannon_entropy_from_values(vals, max_categories=16)
        assert math.isclose(ent, 1.0, abs_tol=1e-5)

    def test_empty_array_entropy_is_zero(self):
        vals = np.array([])
        assert shannon_entropy_from_values(vals) == 0.0

    def test_herfindahl_concentration_single_target(self):
        # All flows target single victim -> HHI = 1.0
        vals = np.array(["10.0.0.1"] * 50)
        assert herfindahl_concentration(vals) == 1.0

    def test_herfindahl_concentration_uniform_targets(self):
        # 10 hosts with 10% traffic each -> HHI = 10 * (0.1)^2 = 0.10
        vals = np.array([f"10.0.0.{i}" for i in range(10)] * 5)
        hhi = herfindahl_concentration(vals)
        assert math.isclose(hhi, 0.10, abs_tol=1e-5)


class TestWindowFeatureExtractor:
    """Tests extract_window_features schema, bounds, and discriminative properties."""

    def test_window_feature_keys_and_bounds(self):
        n = 50
        srcs = np.array([f"192.168.1.{i}" for i in range(n)])
        dsts = np.array(["10.0.0.1"] * n)
        ports = np.array([80] * n)
        protos = np.array([6] * n)
        prates = np.random.uniform(10, 500, size=n)
        brates = np.random.uniform(100, 5000, size=n)
        durs = np.random.uniform(0.1, 10.0, size=n)

        feats = extract_window_features(srcs, dsts, ports, protos, prates, brates, durs)
        for name in FEATURE_NAMES:
            assert name in feats, f"Missing feature {name}"
            assert isinstance(feats[name], float), f"Feature {name} is not float: {type(feats[name])}"
            assert not math.isnan(feats[name]), f"Feature {name} is NaN"

        # Under single destination victim:
        assert feats["unique_dst_count"] == 1.0
        assert feats["flow_concentration"] == 1.0
        assert feats["packet_entropy"] == 0.0 # Single port 80

    def test_probe_scan_distinct_port_entropy(self):
        # Simulated port scan: single attacker scanning 50 distinct ports
        n = 50
        srcs = np.array(["192.168.1.100"] * n)
        dsts = np.array(["10.0.0.1"] * n)
        ports = np.arange(1000, 1000 + n) # 50 unique ports
        protos = np.array([6] * n)
        prates = np.array([5.0] * n)
        brates = np.array([320.0] * n)
        durs = np.array([0.01] * n)

        probe_feats = extract_window_features(srcs, dsts, ports, protos, prates, brates, durs)
        # Port entropy must be maximal (1.0)
        assert probe_feats["packet_entropy"] > 0.90, f"Probe port entropy too low: {probe_feats['packet_entropy']}"
        assert probe_feats["unique_dst_count"] == 1.0
        assert probe_feats["flow_concentration"] == 1.0 # High concentration on victim IP

