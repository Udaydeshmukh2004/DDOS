"""
Unit and integration tests for Level B: Live Synchronized Twin & What-If Simulator.

Verifies:
1. Pure read-only safety boundary (no controller/mitigation/traffic_scheduler imports).
2. Live state telemetry parsing and synchronization status.
3. Live what-if simulation calculation against active telemetry.
4. API endpoints (GET state, POST simulate, GET simulations) and 405 preservation.
5. SOC UI integrity (no Math.random, forbidden strings absent, route registered).
"""

from __future__ import annotations

import ast
import csv
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from twin.live_twin import (
    get_live_twin_state,
    read_live_simulations,
    simulate_live_whatif,
)
from twin.validate import TwinValidationError


class TestLevelBSafetyBoundary(unittest.TestCase):
    def test_live_twin_forbids_unsafe_imports(self):
        rel = "twin/live_twin.py"
        src_path = _ROOT / rel
        self.assertTrue(src_path.is_file())
        tree = ast.parse(src_path.read_text(encoding="utf-8"))
        mods = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.extend(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.append(node.module)
        joined = " ".join(mods)
        self.assertNotIn("mitigation", joined)
        self.assertNotIn("flow_monitor", joined)
        self.assertNotIn("traffic_scheduler", joined)

    def test_live_twin_no_mitigation_callables(self):
        import twin.live_twin as lt

        self.assertFalse(hasattr(lt, "handle_alert"))
        self.assertFalse(hasattr(lt, "install_drop_flow"))
        self.assertFalse(hasattr(lt, "launch_mininet"))


class TestLevelBLiveState(unittest.TestCase):
    def test_live_state_missing_files_clean_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty_logs = Path(tmp) / "logs"
            empty_logs.mkdir()
            state = get_live_twin_state(empty_logs)
            self.assertEqual(state["schema"], "intellishield.twin.live_state.v1")
            self.assertEqual(state["freshness"], "UNAVAILABLE")
            self.assertEqual(state["sync_status"], "DISCONNECTED")
            self.assertEqual(state["control"], "READ_ONLY")
            self.assertFalse(state["mutates_controller"])
            self.assertFalse(state["mutates_mitigation"])
            self.assertFalse(state["launches_mininet"])
            self.assertEqual(state["topology"]["switch_count"], 0)
            self.assertEqual(state["telemetry"]["current_packet_rate"], 0.0)

    def test_live_state_populated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "logs"
            logs.mkdir()
            topo = {
                "connection_state": "CONNECTED",
                "controller_connected": True,
                "schema_version": 1,
                "switches": [{"dpid": 1, "dpid_hex": "0000000000000001", "name": "s1"}],
                "hosts": [{"mac": "00:00:00:00:00:01", "port": 1}],
                "links": [{"src": "host:00:00:00:00:00:01", "dst": "switch:s1", "port": 1}],
                "updated_at": "2026-10-21T14:00:00Z",
                "updated_at_unix": time.time(),
            }
            (logs / "topology_status.json").write_text(json.dumps(topo), encoding="utf-8")

            flow_lines = [
                "timestamp,switch_id,src_mac,dst_mac,in_port,priority,packet_count,byte_count,packet_rate,byte_rate,duration_sec",
                "2026-10-21 14:00:00,1,00:00:00:00:00:01,00:00:00:00:00:02,1,1,100,1000,50.0,5000.0,10",
                "2026-10-21 14:00:00,1,00:00:00:00:00:02,00:00:00:00:00:01,2,1,120,1200,60.0,6000.0,10",
            ]
            (logs / "flow_stats.csv").write_text("\n".join(flow_lines), encoding="utf-8")

            state = get_live_twin_state(logs)
            self.assertEqual(state["freshness"], "LIVE")
            self.assertEqual(state["sync_status"], "SYNCHRONIZED")
            self.assertTrue(state["controller_connected"])
            self.assertEqual(state["topology"]["switch_count"], 1)
            self.assertEqual(state["topology"]["host_count"], 1)
            self.assertEqual(state["telemetry"]["current_packet_rate"], 110.0)
            self.assertEqual(state["telemetry"]["current_byte_rate"], 11000.0)
            self.assertEqual(state["telemetry"]["active_flow_count"], 2)


class TestLevelBLiveWhatIf(unittest.TestCase):
    def test_live_whatif_simulation_math_and_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            logs.mkdir()

            flow_lines = [
                "timestamp,switch_id,src_mac,dst_mac,in_port,priority,packet_count,byte_count,packet_rate,byte_rate,duration_sec",
                "2026-10-21 14:00:00,1,00:00:00:00:00:01,00:00:00:00:00:02,1,1,100,1000,20.0,2000.0,10",
            ]
            (logs / "flow_stats.csv").write_text("\n".join(flow_lines), encoding="utf-8")

            sim = simulate_live_whatif(
                "S2",
                overrides={"attack_sec": 40, "syn_rate": 8000.0},
                seed=42,
                target_host="h2",
                logs_dir=logs,
                persist=True,
                root=root,
            )

            self.assertEqual(sim["schema"], "intellishield.twin.live_whatif.v1")
            self.assertEqual(sim["scenario_id"], "S2")
            self.assertEqual(sim["target_host"], "h2")
            self.assertEqual(sim["control"], "READ_ONLY")
            self.assertFalse(sim["mutates_controller"])
            self.assertFalse(sim["mutates_mitigation"])
            self.assertFalse(sim["launches_mininet"])

            proj = sim["projected_telemetry"]
            self.assertEqual(proj["variant_duration_sec"], 40.0)
            self.assertEqual(proj["projected_peak_packet_rate"], 8020.0)
            self.assertGreater(proj["rate_surge_multiplier"], 10.0)

            # Check persistence
            self.assertTrue(Path(sim["simulation_path"]).is_file())
            history = read_live_simulations(logs)
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["simulation_id"], sim["simulation_id"])

    def test_unsupported_scenario_raises_validation_error(self):
        with self.assertRaises(TwinValidationError):
            simulate_live_whatif("S99_INVALID", persist=False)


class TestLevelBApiEndpoints(unittest.TestCase):
    def test_api_live_endpoints_and_level_a_405_invariants(self):
        try:
            from fastapi.testclient import TestClient
        except Exception:
            self.skipTest("fastapi TestClient not available")

        try:
            import dashboard.api as api_mod
        except Exception:
            dash_dir = str(_ROOT / "dashboard")
            if dash_dir not in sys.path:
                sys.path.insert(0, dash_dir)
            import api as api_mod

        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "logs"
            logs.mkdir()
            for mod_name in ("dashboard.api", "api"):
                if mod_name in sys.modules:
                    setattr(sys.modules[mod_name], "TWIN_LOGS_DIR", logs)
            api_mod.TWIN_LOGS_DIR = logs
            client = TestClient(api_mod.app)

            # 1. Level B live state endpoint
            r_state = client.get("/api/digital-twin/live/state")
            self.assertEqual(r_state.status_code, 200)
            body_state = r_state.json()
            self.assertEqual(body_state["control"], "READ_ONLY")
            self.assertIn("freshness", body_state)
            self.assertIn("sync_status", body_state)

            # 2. Level B live what-if simulation endpoint
            r_sim = client.post(
                "/api/digital-twin/live/simulate",
                json={
                    "scenario_id": "S2",
                    "overrides": {"attack_sec": 25, "syn_rate": 6000},
                    "target_host": "h2",
                    "persist": True,
                },
            )
            self.assertEqual(r_sim.status_code, 200)
            body_sim = r_sim.json()
            self.assertEqual(body_sim["scenario_id"], "S2")
            self.assertEqual(body_sim["control"], "READ_ONLY")
            self.assertEqual(body_sim["projected_telemetry"]["variant_duration_sec"], 25.0)

            # 3. Level B live simulations list endpoint
            r_list = client.get("/api/digital-twin/live/simulations")
            self.assertEqual(r_list.status_code, 200)
            body_list = r_list.json()
            self.assertEqual(body_list["count"], 1)
            self.assertEqual(body_list["control"], "READ_ONLY")

            # 4. Critical Level A invariant: Level A POST endpoints must STILL return 405
            self.assertEqual(client.post("/api/digital-twin/snapshots").status_code, 405)
            self.assertEqual(client.post("/api/digital-twin/replays").status_code, 405)
            self.assertEqual(client.post("/api/digital-twin/simulations").status_code, 405)

            # 5. POST exec must NOT exist
            self.assertIn(
                client.post("/api/digital-twin/exec", json={"cmd": "ls"}).status_code,
                (404, 405, 422),
            )


class TestLevelBSocUiIntegrity(unittest.TestCase):
    def test_soc_ui_files_satisfy_invariants(self):
        page_src = (_ROOT / "dashboard/static/soc/js/pages/index.js").read_text(encoding="utf-8")
        self.assertIn("renderTwin", page_src)
        self.assertIn("Level B: Live Network Synchronization", page_src)
        self.assertIn("Level B: Interactive What-If Simulator", page_src)
        self.assertIn("data-twin-run-sim", page_src)
        self.assertIn("READ ONLY", page_src)

        # Forbidden strings
        for banned in ("Start Twin Attack", "Launch Mininet", "Promote Model", "/api/digital-twin/exec", "Math.random"):
            self.assertNotIn(banned, page_src)

        # Nav link present in index.html
        html = (_ROOT / "dashboard/static/soc/index.html").read_text(encoding="utf-8")
        self.assertIn("#twin", html)
        self.assertIn("LIVE B", html)

        # Route present in app.js
        app_js = (_ROOT / "dashboard/static/soc/js/app.js").read_text(encoding="utf-8")
        self.assertIn("twin:", app_js)


if __name__ == "__main__":
    unittest.main()

