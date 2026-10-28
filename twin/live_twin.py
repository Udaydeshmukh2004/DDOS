"""
Level B: Read-only live synchronized Digital Twin and what-if simulation.

Observes live network telemetry (switches, learned hosts, flow rates) without
mutating the controller, installing OpenFlow rules, or launching Mininet.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Union

from shared_contracts.timeutil import format_ts, utc_now
from twin.isolation import project_root
from twin.planner import plan_scenario
from twin.validate import TwinValidationError

logger = logging.getLogger("intellishield.twin.live")

PathLike = Union[str, Path]

DEFAULT_STALE_AFTER_SEC = 20.0
FLOW_TAIL_MAX_ROWS = 200


def _attack_duration(plan: Any) -> float:
    sid = str(getattr(plan, "scenario_id", "")).strip().upper()
    if sid == "S1":
        return 0.0
    if sid == "S4":
        b_cnt = getattr(plan, "burst_count", 1)
        b_sec = getattr(plan, "burst_sec", 10)
        ibi_sec = getattr(plan, "inter_burst_interval_sec", 5)
        extra = max(0, b_cnt - 1) * (b_sec + ibi_sec)
        return float(b_sec + extra)
    if sid == "S5":
        a1 = getattr(plan, "attack1_sec", 15)
        a2 = getattr(plan, "attack2_sec", 15)
        return float(a1 + a2)
    return float(getattr(plan, "attack_sec", 30))


def _scenario_nominal_attack_rate(plan: Any) -> float:
    sid = str(getattr(plan, "scenario_id", "")).strip().upper()
    if sid == "S1":
        return 0.0
    if sid == "S2":
        return float(getattr(plan, "syn_rate", 10000.0))
    if sid == "S3":
        return float(getattr(plan, "udp_rate", 12000.0) if hasattr(plan, "udp_rate") else 10000.0)
    if sid == "S4":
        return float(getattr(plan, "burst_rate", 15000.0) if hasattr(plan, "burst_rate") else 12000.0)
    if sid == "S5":
        return float(getattr(plan, "combined_rate", 20000.0) if hasattr(plan, "combined_rate") else 15000.0)
    return 10000.0


def _parse_flow_tail(flow_csv: Path) -> Dict[str, Any]:
    """Parse the most recent flow cycle from flow_stats.csv to extract live traffic rates."""
    if not flow_csv.is_file():
        return {
            "current_packet_rate": 0.0,
            "current_byte_rate": 0.0,
            "active_flow_count": 0,
            "latest_flow_sample_time": None,
        }

    try:
        with flow_csv.open("r", encoding="utf-8", errors="replace") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        if not lines:
            return {
                "current_packet_rate": 0.0,
                "current_byte_rate": 0.0,
                "active_flow_count": 0,
                "latest_flow_sample_time": None,
            }

        header_candidate = [c.strip() for c in lines[0].split(",")]
        has_header = "packet_rate" in header_candidate or "timestamp" in header_candidate
        data_lines = lines[1:] if has_header else lines
        data_lines = data_lines[-FLOW_TAIL_MAX_ROWS:]

        if not data_lines:
            return {
                "current_packet_rate": 0.0,
                "current_byte_rate": 0.0,
                "active_flow_count": 0,
                "latest_flow_sample_time": None,
            }

        # Find latest timestamp
        rows = [list(csv.reader([ln]))[0] for ln in data_lines if ln]
        if not rows:
            return {
                "current_packet_rate": 0.0,
                "current_byte_rate": 0.0,
                "active_flow_count": 0,
                "latest_flow_sample_time": None,
            }

        latest_ts = rows[-1][0] if rows[-1] else None
        # Aggregate flows sharing the latest timestamp cycle
        recent_rows = [r for r in rows if len(r) >= 10 and r[0] == latest_ts]
        if not recent_rows:
            recent_rows = [rows[-1]]

        total_pkt_rate = 0.0
        total_byte_rate = 0.0
        for r in recent_rows:
            try:
                # Standard format: timestamp, switch_id, src_mac, dst_mac, in_port, priority, packet_count, byte_count, packet_rate, byte_rate, ...
                total_pkt_rate += float(r[8])
                total_byte_rate += float(r[9])
            except (IndexError, ValueError):
                continue

        return {
            "current_packet_rate": round(total_pkt_rate, 2),
            "current_byte_rate": round(total_byte_rate, 2),
            "active_flow_count": len(recent_rows),
            "latest_flow_sample_time": latest_ts,
        }
    except Exception as exc:
        logger.debug("Error parsing flow_stats.csv: %s", exc)
        return {
            "current_packet_rate": 0.0,
            "current_byte_rate": 0.0,
            "active_flow_count": 0,
            "latest_flow_sample_time": None,
        }


def get_live_twin_state(
    logs_dir: Optional[PathLike] = None,
    *,
    stale_after_sec: float = DEFAULT_STALE_AFTER_SEC,
) -> Dict[str, Any]:
    """
    Produce the read-only live synchronized digital twin state.

    Reads topology_status.json and flow_stats.csv from the logs directory.
    Does not mutate controller state or inject network packets.
    """
    base_logs = Path(logs_dir) if logs_dir else project_root() / "logs"
    topo_path = base_logs / "topology_status.json"
    flow_path = base_logs / "flow_stats.csv"

    now_unix = time.time()
    raw_topo: Dict[str, Any] = {}
    freshness = "UNAVAILABLE"
    age_seconds: Optional[float] = None
    controller_connected = False

    if topo_path.is_file():
        try:
            raw_topo = json.loads(topo_path.read_text(encoding="utf-8"))
            if isinstance(raw_topo, dict):
                controller_connected = bool(raw_topo.get("controller_connected", False))
                up_unix = raw_topo.get("updated_at_unix")
                if isinstance(up_unix, (int, float)):
                    age_seconds = round(max(0.0, now_unix - float(up_unix)), 2)
                    freshness = "LIVE" if age_seconds <= stale_after_sec else "STALE"
                else:
                    mtime = topo_path.stat().st_mtime
                    age_seconds = round(max(0.0, now_unix - mtime), 2)
                    freshness = "LIVE" if age_seconds <= stale_after_sec else "STALE"
        except Exception as exc:
            logger.debug("Failed reading topology_status.json: %s", exc)

    switches = raw_topo.get("switches", [])
    hosts = raw_topo.get("hosts", [])
    links = raw_topo.get("links", [])

    telemetry = _parse_flow_tail(flow_path)

    sync_status = "SYNCHRONIZED" if freshness == "LIVE" and controller_connected else (
        "DEGRADED" if freshness == "STALE" else "DISCONNECTED"
    )

    return {
        "schema": "intellishield.twin.live_state.v1",
        "level": "Level B (Read-Only Live Synchronized Twin)",
        "freshness": freshness,
        "sync_status": sync_status,
        "controller_connected": controller_connected,
        "last_sync_time": raw_topo.get("updated_at"),
        "age_seconds": age_seconds,
        "topology": {
            "switch_count": len(switches),
            "host_count": len(hosts),
            "link_count": len(links),
            "switches": switches,
            "hosts": hosts,
            "links": links,
        },
        "telemetry": telemetry,
        "control": "READ_ONLY",
        "mutates_controller": False,
        "mutates_mitigation": False,
        "launches_mininet": False,
        "note": "Level B read-only synchronized network twin. Observational telemetry only.",
    }


def simulate_live_whatif(
    scenario_id: str,
    *,
    overrides: Optional[Mapping[str, Any]] = None,
    seed: int = 42,
    target_host: str = "h2",
    logs_dir: Optional[PathLike] = None,
    persist: bool = True,
    root: Optional[PathLike] = None,
) -> Dict[str, Any]:
    """
    Simulate a what-if attack scenario variant against the live network state.

    Uses current live traffic telemetry as baseline and evaluates projected impact.
    Does not transmit packets or alter controller rules.
    """
    sid = str(scenario_id).strip().upper()
    if sid not in {"S1", "S2", "S3", "S4", "S5"}:
        raise TwinValidationError(f"unsupported scenario_id: {scenario_id!r}")

    ov = dict(overrides or {})
    base_logs = Path(logs_dir) if logs_dir else (Path(root) if root else project_root()) / "logs"
    live_state = get_live_twin_state(base_logs)

    baseline_plan = plan_scenario(sid, seed=seed)
    variant_plan = plan_scenario(sid, overrides=ov, seed=seed)

    b_dur = _attack_duration(baseline_plan)
    v_dur = _attack_duration(variant_plan)

    live_pkt_s = float(live_state.get("telemetry", {}).get("current_packet_rate", 0.0))
    variant_rate = float(
        ov.get("syn_rate")
        or ov.get("udp_rate")
        or ov.get("intensity")
        or _scenario_nominal_attack_rate(variant_plan)
    )

    projected_rate = round(live_pkt_s + variant_rate, 2)
    rate_multiplier = round(projected_rate / max(1.0, live_pkt_s), 2)

    # Param deltas
    param_delta: Dict[str, Any] = {}
    for k in sorted(set(baseline_plan.parameters) | set(variant_plan.parameters)):
        bv = baseline_plan.parameters.get(k)
        vv = variant_plan.parameters.get(k)
        if bv != vv:
            param_delta[k] = {"baseline": bv, "variant": vv}

    # Capacity & Impact Assessment
    nominal_link_capacity_pkt_s = 20000.0
    load_ratio = projected_rate / nominal_link_capacity_pkt_s
    severity = "LOW"
    if load_ratio > 0.8:
        severity = "CRITICAL"
    elif load_ratio > 0.4:
        severity = "HIGH"
    elif load_ratio > 0.1:
        severity = "MEDIUM"

    sim_hash_content = {
        "sid": sid,
        "seed": seed,
        "ov": ov,
        "live_pkt_s": live_pkt_s,
        "target": target_host,
    }
    sim_id = "twinlive-" + hashlib.sha256(
        json.dumps(sim_hash_content, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:12]

    result: Dict[str, Any] = {
        "schema": "intellishield.twin.live_whatif.v1",
        "simulation_id": sim_id,
        "created_at": format_ts(utc_now()),
        "scenario_id": sid,
        "target_host": target_host,
        "seed": seed,
        "overrides": ov,
        "parameter_delta": param_delta,
        "live_baseline": {
            "current_packet_rate": live_pkt_s,
            "current_byte_rate": float(live_state.get("telemetry", {}).get("current_byte_rate", 0.0)),
            "active_flow_count": live_state.get("telemetry", {}).get("active_flow_count", 0),
            "freshness": live_state.get("freshness"),
            "controller_connected": live_state.get("controller_connected"),
        },
        "projected_telemetry": {
            "baseline_attack_rate": _scenario_nominal_attack_rate(baseline_plan),
            "variant_attack_rate": variant_rate,
            "projected_peak_packet_rate": projected_rate,
            "rate_surge_multiplier": rate_multiplier,
            "baseline_duration_sec": b_dur,
            "variant_duration_sec": v_dur,
            "duration_delta_sec": round(v_dur - b_dur, 3),
        },
        "impact_assessment": {
            "projected_load_ratio": round(load_ratio, 4),
            "estimated_severity": severity,
            "target_switch": "s1",
            "target_host": target_host,
            "mitigation_required": severity in {"HIGH", "CRITICAL"},
        },
        "control": "READ_ONLY",
        "mutates_controller": False,
        "mutates_mitigation": False,
        "launches_mininet": False,
        "notes": (
            "Live network what-if simulation evaluated against active telemetry baseline. "
            "Evaluated entirely in plan space; no real traffic injected."
        ),
    }

    if persist:
        out_dir = base_logs / "twin" / "live_simulations" / sim_id
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "live_whatif_result.json"
        path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        result["artifact_dir"] = str(out_dir)
        result["simulation_path"] = str(path)

    return result


def read_live_simulations(
    logs_dir: Optional[PathLike] = None,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """Read recent live what-if simulation records, newest first."""
    base_logs = Path(logs_dir) if logs_dir else project_root() / "logs"
    sim_dir = base_logs / "twin" / "live_simulations"
    if not sim_dir.is_dir():
        return []

    results: List[Dict[str, Any]] = []
    try:
        subdirs = sorted(
            [d for d in sim_dir.iterdir() if d.is_dir()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for d in subdirs[:limit]:
            f = d / "live_whatif_result.json"
            if f.is_file():
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        results.append(data)
                except Exception:
                    continue
    except Exception as exc:
        logger.debug("Error reading live simulations: %s", exc)

    return results

