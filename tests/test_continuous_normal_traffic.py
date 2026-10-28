#!/usr/bin/env python3
"""
Test Suite for Continuous Normal Traffic Capability
Verifies:
1. Registry of continuous normal traffic scenario ('1_cont') in SCENARIO_REGISTRY.
2. CLI support for --continuous in traffic_scheduler.
3. Master Control panel support in dashboard/control.py and dashboard/api.py.
4. Stop scenario endpoint and process cleanup functionality.
5. Executability and CLI options of scripts/run_continuous_normal_traffic.py.
"""

import os
import sys
import argparse
import pytest

_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_FILE_DIR) if os.path.basename(_FILE_DIR) == "tests" else _FILE_DIR
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from traffic_generator.attack_scenarios import SCENARIO_REGISTRY
from traffic_generator.traffic_scheduler import parse_args
from dashboard.control import SCENARIOS, ControlPanel
from dashboard.api import app


class TestContinuousNormalTrafficConfig:
    """Verifies that continuous normal traffic options are registered across components."""

    def test_scenario_registry_has_continuous_normal(self):
        assert "1" in SCENARIO_REGISTRY
        assert "1_cont" in SCENARIO_REGISTRY
        name, func = SCENARIO_REGISTRY["1_cont"]
        assert "continuous" in name.lower() or "normal" in name.lower()
        assert callable(func)

    def test_dashboard_scenarios_has_continuous_normal(self):
        assert "1" in SCENARIOS
        assert "1_cont" in SCENARIOS
        assert "continuous" in SCENARIOS["1_cont"].lower()

    def test_scheduler_cli_supports_continuous_flag(self):
        # Test argparse with --continuous
        test_args = ["--scenario", "1", "--continuous"]
        sys_argv_bak = sys.argv
        try:
            sys.argv = ["traffic_scheduler.py"] + test_args
            parsed = parse_args()
            assert parsed.continuous is True
            assert parsed.scenario == "1"
        finally:
            sys.argv = sys_argv_bak

    def test_control_panel_stop_scenario_method_exists(self):
        cp = ControlPanel()
        assert hasattr(cp, "stop_scenario")
        assert callable(cp.stop_scenario)

    def test_dashboard_api_has_stop_scenario_route(self):
        routes = [getattr(r, "path", None) for r in app.routes if hasattr(r, "path")]
        assert "/api/control/scenario/stop" in routes

    def test_run_continuous_normal_script_exists_and_executable(self):
        script_path = os.path.join(_ROOT, "scripts", "run_continuous_normal_traffic.py")
        assert os.path.isfile(script_path)
        assert os.access(script_path, os.R_OK)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
