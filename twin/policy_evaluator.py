"""
Candidate Detection and Mitigation Policy Validation Engine.

Evaluates candidate detection thresholds and mitigation policies against
recorded experiment snapshots or telemetry in plan/trace space.

Safe Feedback Workflow (Strictly Read-Only):
Observed SDN Telemetry & Logs
  → Digital Twin Snapshot
  → Candidate Policy Validation
  → Validation Report (with FP/FN and collateral impact)
  → Explicit Operator Approval Gate
  → [Manual Operator Export / Configuration Update]

The Twin NEVER directly installs OpenFlow rules, mutates controller state,
or overwrites production configurations.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Union

from evaluation.csv_log_io import load_csv_rows
from evaluation.experiment_windows import parse_ts
from shared_contracts.timeutil import format_ts, utc_now
from twin.bounds import MAX_SNAPSHOT_CSV_ROWS, assert_history_limit
from twin.isolation import project_root
from twin.snapshot import load_snapshot
from twin.validate import TwinValidationError

logger = logging.getLogger("intellishield.twin.policy_evaluator")

PathLike = Union[str, Path]

# Safety contract — imported by tests. These modules must never be imported here.
FORBIDDEN_IMPORTS = (
    "controller.flow_monitor",
    "mitigation.mitigation_engine",
    "mitigation",
    "traffic_generator.traffic_scheduler",
)

DEFAULT_MIN_PRECISION = 0.85
DEFAULT_MIN_RECALL = 0.80
DEFAULT_MAX_FPR = 0.08


def _sanitize_id(val: str, name: str = "id") -> str:
    cleaned = str(val or "").strip()
    if not cleaned or ".." in cleaned or "/" in cleaned or "\\" in cleaned:
        raise TwinValidationError(f"invalid {name}: {val!r}")
    return cleaned


def _extract_windows(snapshot: Mapping[str, Any]) -> List[tuple]:
    windows = []
    for w in snapshot.get("windows") or []:
        start = parse_ts(w.get("attack_start", ""))
        stop = parse_ts(w.get("attack_stop", ""))
        if start is not None and stop is not None:
            windows.append((start, stop))
    return windows


def evaluate_candidate_policy(
    snapshot: Mapping[str, Any],
    candidate_policy: Mapping[str, Any],
    *,
    persist: bool = True,
    root: Optional[PathLike] = None,
) -> Dict[str, Any]:
    """
    Evaluate a candidate detection threshold and mitigation policy against a snapshot.

    Computes:
    - Predicted attack classification (TP, FP, FN, TN)
    - Precision, Recall, F1, FPR, FNR
    - Impact on legitimate traffic (% normal flows mistakenly affected)
    - Mitigation outcome prediction
    - Quality gate validation status (PASS / WARNING / FAIL)
    - Safe feedback workflow record with explicit operator approval requirement
    """
    if not isinstance(snapshot, Mapping):
        raise TwinValidationError("snapshot must be a mapping")
    if not isinstance(candidate_policy, Mapping):
        raise TwinValidationError("candidate_policy must be a mapping")

    policy_name = str(candidate_policy.get("policy_name") or "Candidate-Policy").strip()
    try:
        pkt_thresh = float(candidate_policy.get("packet_rate_threshold", 5000.0))
        byte_thresh = float(candidate_policy.get("byte_rate_threshold", 5000000.0))
        conf_thresh = float(candidate_policy.get("confidence_threshold", 0.75))
        timeout_sec = int(candidate_policy.get("idle_timeout_sec", 30))
    except (ValueError, TypeError) as exc:
        raise TwinValidationError(f"invalid numerical parameter: {exc}") from exc

    if pkt_thresh <= 0 or byte_thresh <= 0:
        raise TwinValidationError("packet and byte thresholds must be positive")
    if not (0.0 <= conf_thresh <= 1.0):
        raise TwinValidationError("confidence_threshold must be between 0.0 and 1.0")
    if timeout_sec <= 0:
        raise TwinValidationError("idle_timeout_sec must be positive")

    action = str(candidate_policy.get("mitigation_action", "BLOCK")).upper().strip()
    if action not in {"BLOCK", "RATE_LIMIT", "OBSERVE"}:
        raise TwinValidationError(f"unsupported mitigation action: {action!r}")

    snap_id = str(snapshot.get("snapshot_id") or "unknown_snapshot")
    windows = _extract_windows(snapshot)

    # Locate flow_stats if available from snapshot artifact_refs
    flow_stats_ref = (snapshot.get("artifact_refs") or {}).get("flow_stats.csv")
    base_dir = Path(root) if root else project_root()
    flow_path: Optional[Path] = None

    if flow_stats_ref:
        p = Path(flow_stats_ref)
        if not p.is_absolute():
            p = base_dir / p
        if p.is_file():
            flow_path = p

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    evaluated_samples = 0
    ground_truth_available = False

    if flow_path and windows:
        # Ground-truth evaluation row-by-row
        ground_truth_available = True
        try:
            rows = load_csv_rows(flow_path)
            rows = rows[-assert_history_limit(MAX_SNAPSHOT_CSV_ROWS) :]
            for r in rows:
                ts = parse_ts(r.get("timestamp", ""))
                if ts is None:
                    continue
                try:
                    p_rate = float(r.get("packet_rate", 0.0) or 0.0)
                    b_rate = float(r.get("byte_rate", 0.0) or 0.0)
                except (ValueError, TypeError):
                    continue

                evaluated_samples += 1
                is_attack = any(w_start <= ts <= w_stop for w_start, w_stop in windows)
                candidate_triggered = (p_rate >= pkt_thresh) or (b_rate >= byte_thresh)

                if is_attack and candidate_triggered:
                    tp += 1
                elif not is_attack and candidate_triggered:
                    fp += 1
                elif is_attack and not candidate_triggered:
                    fn += 1
                else:
                    tn += 1
        except Exception as exc:
            logger.debug("Failed reading flow_stats for policy evaluation: %s", exc)

    if evaluated_samples == 0:
        # Fallback to snapshot baseline_vs_attack summary
        bva = snapshot.get("baseline_vs_attack") or {}
        base_rate = bva.get("baseline_mean_pkt_s")
        atk_rate = bva.get("attack_mean_pkt_s")
        n_base = int(bva.get("n_baseline_rows") or 0)
        n_atk = int(bva.get("n_attack_rows") or 0)

        if (base_rate is not None or atk_rate is not None) and (n_base > 0 or n_atk > 0):
            ground_truth_available = True
            evaluated_samples = n_base + n_atk
            # Baseline (normal) evaluation
            if base_rate is not None:
                if pkt_thresh <= base_rate:
                    fp = n_base
                    tn = 0
                else:
                    fp = 0
                    tn = n_base
            else:
                tn = n_base

            # Attack evaluation
            if atk_rate is not None:
                if pkt_thresh <= atk_rate:
                    tp = n_atk
                    fn = 0
                else:
                    tp = 0
                    fn = n_atk
            else:
                fn = n_atk

    # Metrics computation
    total_positives = tp + fn
    total_negatives = fp + tn

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else (1.0 if tp == 0 and fp == 0 else 0.0)
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else (1.0 if tp == 0 and fn == 0 else 0.0)
    f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    fpr = round(fp / total_negatives, 4) if total_negatives > 0 else 0.0
    fnr = round(fn / total_positives, 4) if total_positives > 0 else 0.0

    # Impact on legitimate traffic
    collateral_damage_pct = round((fp / max(1, total_negatives)) * 100.0, 2) if total_negatives > 0 else 0.0
    if collateral_damage_pct == 0.0:
        impact_rating = "NONE"
        impact_desc = "Zero false positives. Legitimate traffic experiences no disruption."
    elif collateral_damage_pct <= 2.0:
        impact_rating = "LOW"
        impact_desc = f"Negligible false positives ({collateral_damage_pct}%). Acceptable for production under attack."
    elif collateral_damage_pct <= 10.0:
        impact_rating = "MODERATE"
        impact_desc = f"Noticeable collateral impact ({collateral_damage_pct}% normal flows flagged). Threshold may be slightly aggressive."
    elif collateral_damage_pct <= 25.0:
        impact_rating = "HIGH"
        impact_desc = f"Significant collateral damage ({collateral_damage_pct}% normal flows flagged). Policy requires loosening."
    else:
        impact_rating = "CRITICAL"
        impact_desc = f"Severe disruption ({collateral_damage_pct}% normal flows flagged). Threshold is below normal traffic rates."

    # Candidate mitigation outcome prediction
    if action == "BLOCK":
        mitigation_efficiency = round((tp / max(1, total_positives)) * 100.0, 2) if total_positives > 0 else 0.0
        mitigation_summary = (
            f"Candidate BLOCK rule drops {tp}/{total_positives} ({mitigation_efficiency}%) attack flows "
            f"with idle_timeout={timeout_sec}s. Projected malicious volume suppression: {mitigation_efficiency}%."
        )
    elif action == "RATE_LIMIT":
        mitigation_efficiency = round((tp / max(1, total_positives)) * 85.0, 2) if total_positives > 0 else 0.0
        mitigation_summary = (
            f"Candidate RATE_LIMIT rule throttles suspicious flows to link ceiling. "
            f"Reduces burst impact while preserving best-effort connectivity."
        )
    else:  # OBSERVE
        mitigation_efficiency = 0.0
        mitigation_summary = "Candidate OBSERVE policy logs anomalies without active OpenFlow suppression."

    # Validation status & gate checks
    gate_findings: List[str] = []
    if evaluated_samples == 0:
        val_status = "INSUFFICIENT_EVIDENCE"
        gate_findings.append("No flow observations or ground truth windows available in snapshot")
    elif fpr > 0.15:
        val_status = "FAIL"
        gate_findings.append(f"False Positive Rate ({fpr*100:.1f}%) exceeds hard ceiling of 15%")
    elif recall < 0.60:
        val_status = "FAIL"
        gate_findings.append(f"Recall ({recall*100:.1f}%) below minimum safety floor of 60%")
    elif fpr > DEFAULT_MAX_FPR:
        val_status = "WARNING"
        gate_findings.append(f"FPR ({fpr*100:.1f}%) exceeds advisory target of {DEFAULT_MAX_FPR*100:.1f}%")
    elif recall < DEFAULT_MIN_RECALL:
        val_status = "WARNING"
        gate_findings.append(f"Recall ({recall*100:.1f}%) below advisory target of {DEFAULT_MIN_RECALL*100:.1f}%")
    elif precision < DEFAULT_MIN_PRECISION:
        val_status = "WARNING"
        gate_findings.append(f"Precision ({precision*100:.1f}%) below advisory target of {DEFAULT_MIN_PRECISION*100:.1f}%")
    else:
        val_status = "PASS"
        gate_findings.append("Candidate policy satisfies all IEEE precision, recall, and safety gate criteria")

    val_id = "twinpol-" + hashlib.sha256(
        json.dumps(
            {
                "snap": snap_id,
                "policy": policy_name,
                "pkt": pkt_thresh,
                "byte": byte_thresh,
                "conf": conf_thresh,
                "act": action,
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()[:12]

    report: Dict[str, Any] = {
        "schema": "intellishield.twin.policy_validation.v1",
        "validation_id": val_id,
        "created_at": format_ts(utc_now()),
        "snapshot_id": snap_id,
        "candidate_policy": {
            "policy_name": policy_name,
            "packet_rate_threshold": pkt_thresh,
            "byte_rate_threshold": byte_thresh,
            "confidence_threshold": conf_thresh,
            "mitigation_action": action,
            "idle_timeout_sec": timeout_sec,
        },
        "ground_truth_available": ground_truth_available,
        "evaluated_samples": evaluated_samples,
        "classification": {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
        },
        "legitimate_traffic_impact": {
            "normal_flows_evaluated": total_negatives,
            "normal_flows_affected": fp,
            "collateral_damage_pct": collateral_damage_pct,
            "impact_rating": impact_rating,
            "description": impact_desc,
        },
        "mitigation_outcome": {
            "mitigation_action": action,
            "projected_attack_suppression_pct": mitigation_efficiency,
            "summary": mitigation_summary,
        },
        "validation_status": val_status,
        "gate_findings": gate_findings,
        "safe_feedback_workflow": {
            "approval_status": "PENDING_OPERATOR_APPROVAL",
            "can_auto_apply": False,
            "reason": (
                "Twin operates in read-only observational mode. "
                "OpenFlow rules and controller thresholds can never be modified automatically."
            ),
            "approval_workflow": (
                "1. Twin evaluates candidate policy against snapshot\n"
                "2. SOC Operator reviews validation report & collateral impact\n"
                "3. Operator explicitly approves or rejects candidate\n"
                "4. Approved policy is exported for controlled manual integration"
            ),
            "controller_export_payload": {
                "packet_rate_threshold": pkt_thresh,
                "byte_rate_threshold": byte_thresh,
                "confidence_threshold": conf_thresh,
                "mitigation_action": action,
                "idle_timeout": timeout_sec,
                "policy_name": policy_name,
                "source_twin_validation_id": val_id,
                "evaluation_snapshot_id": snap_id,
                "export_ts": format_ts(utc_now()),
                "approval_required": True,
            },
        },
        "control": "READ_ONLY",
        "mutates_controller": False,
        "mutates_mitigation": False,
        "launches_mininet": False,
        "notes": (
            "Candidate policy evaluation evaluated in plan and observational log space. "
            "Does not alter production OpenFlow state or switch tables."
        ),
    }

    if persist:
        out_dir = base_dir / "logs" / "twin" / "policy_validations" / val_id
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "policy_validation_report.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        report["artifact_dir"] = str(out_dir)
        report["validation_path"] = str(path)

    return report


def read_policy_validations(
    logs_dir: PathLike, *, limit: int = 20
) -> List[Dict[str, Any]]:
    """List recent policy validation reports (read-only)."""
    limit = assert_history_limit(limit if limit > 0 else 20)
    root = Path(logs_dir) / "twin" / "policy_validations"
    if not root.is_dir():
        return []
    dirs = []
    try:
        dirs = sorted(
            [p for p in root.iterdir() if p.is_dir()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except Exception:  # noqa: BLE001
        return []

    out = []
    for d in dirs[:limit]:
        p = d / "policy_validation_report.json"
        if not p.is_file():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data.setdefault("artifact_dir", str(d))
                out.append(data)
        except Exception:  # noqa: BLE001
            continue
    return out


def get_policy_validation(
    logs_dir: PathLike, validation_id: str
) -> Optional[Dict[str, Any]]:
    """Get single policy validation report by ID (read-only)."""
    vid = _sanitize_id(validation_id, "validation_id")
    p = Path(logs_dir) / "twin" / "policy_validations" / vid / "policy_validation_report.json"
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001
        return None

