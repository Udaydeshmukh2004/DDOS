"""
Counterfactual Explanation Engine (R5 Enhancement).

Computes deterministic, actionable counterfactual remediation guidance:
"What minimal changes to traffic features would flip the decision from ATTACK to NORMAL?"

Uses exact Decision Tree geometry when available, or heuristic nominal bounds as fallback.
No non-deterministic solvers, no black-box approximations.
"""

from __future__ import annotations

import math
from typing import Any, List, Optional, Sequence, Tuple

from ml_models.explainer import NORMAL_RANGES
from xai.models import CounterfactualExplanation, CounterfactualStep
from xai.tree_path import is_decision_tree_like

_EPSILON = 1e-4
_CLASS_NORMAL = 0
_CLASS_ATTACK = 1


def compute_counterfactual(
    vector: Sequence[float],
    feature_names: Sequence[str],
    *,
    decision_tree: Any = None,
    scaler: Any = None,
    target_decision: str = "NORMAL",
    max_features: int = 5,
) -> CounterfactualExplanation:
    """
    Compute minimal counterfactual perturbation to transition to target_decision.

    Never raises; returns empty/unachievable on incompatible models or invalid vectors.
    """
    if not vector or len(vector) != len(feature_names):
        return CounterfactualExplanation(
            achievable=False,
            target_decision=target_decision,
            summary="Counterfactual unavailable: invalid or mismatched feature vector.",
            guidance=[],
        )

    # 1. Decision Tree geometric counterfactual (exact and model-grounded)
    if is_decision_tree_like(decision_tree) and scaler is not None:
        try:
            return _dt_counterfactual(
                vector,
                feature_names,
                decision_tree,
                scaler,
                target_decision=target_decision,
                max_features=max_features,
            )
        except Exception:  # noqa: BLE001
            pass

    # 2. Heuristic fallback vs nominal baseline ranges
    return _heuristic_counterfactual(
        vector,
        feature_names,
        target_decision=target_decision,
        max_features=max_features,
    )


def _dt_counterfactual(
    vector: Sequence[float],
    feature_names: Sequence[str],
    decision_tree: Any,
    scaler: Any,
    *,
    target_decision: str = "NORMAL",
    max_features: int = 5,
) -> CounterfactualExplanation:
    """Find the closest leaf predicting target_decision in scaled feature space."""
    import numpy as np

    tree = decision_tree.tree_
    X = np.asarray([list(vector)], dtype=float)
    X_scaled = scaler.transform(X)[0]

    feature = tree.feature
    threshold = tree.threshold
    children_left = tree.children_left
    children_right = tree.children_right
    value = tree.value

    # Identify target class index
    classes = getattr(decision_tree, "classes_", [0, 1])
    target_cls_idx = 0
    for idx, c in enumerate(classes):
        if str(c).upper() in (target_decision.upper(), "0") and target_decision.upper() == "NORMAL":
            target_cls_idx = idx
            break
        elif str(c).upper() in (target_decision.upper(), "1") and target_decision.upper() == "ATTACK":
            target_cls_idx = idx
            break

    # Find all target leaves and their root-to-leaf constraints
    # Constraint: list of (feature_idx, operator "<=" or ">", threshold_val)
    paths_to_leaves: List[Tuple[int, List[Tuple[int, str, float]]]] = []

    def dfs(node_id: int, current_path: List[Tuple[int, str, float]]):
        if children_left[node_id] == children_right[node_id]:  # leaf
            pred_class = int(value[node_id][0].argmax())
            if pred_class == target_cls_idx:
                paths_to_leaves.append((node_id, list(current_path)))
            return

        feat = int(feature[node_id])
        thr = float(threshold[node_id])

        # Left: feat <= thr
        current_path.append((feat, "<=", thr))
        dfs(children_left[node_id], current_path)
        current_path.pop()

        # Right: feat > thr
        current_path.append((feat, ">", thr))
        dfs(children_right[node_id], current_path)
        current_path.pop()

    dfs(0, [])

    if not paths_to_leaves:
        return _heuristic_counterfactual(vector, feature_names, target_decision=target_decision, max_features=max_features)

    # Evaluate distance to satisfy each leaf's constraints from current X_scaled
    best_leaf = None
    min_l2 = float("inf")
    best_deltas: List[Tuple[int, float, str, float]] = []

    means = getattr(scaler, "mean_", None)
    scales = getattr(scaler, "scale_", None)

    for leaf_id, constraints in paths_to_leaves:
        # For each feature, find required interval [lower_bound, upper_bound]
        lower_bounds: dict[int, float] = {}
        upper_bounds: dict[int, float] = {}

        for f_idx, op, thr in constraints:
            if op == "<=":
                upper_bounds[f_idx] = min(upper_bounds.get(f_idx, float("inf")), thr)
            else:
                lower_bounds[f_idx] = max(lower_bounds.get(f_idx, float("-inf")), thr)

        # Check if constraints are mutually satisfiable
        feasible = True
        for f_idx in set(lower_bounds.keys()).intersection(upper_bounds.keys()):
            if lower_bounds[f_idx] >= upper_bounds[f_idx]:
                feasible = False
                break
        if not feasible:
            continue

        # Compute required scaled perturbation
        leaf_deltas = []
        l2_sum = 0.0

        all_feats = set(lower_bounds.keys()).union(upper_bounds.keys())
        for f_idx in all_feats:
            curr_val = X_scaled[f_idx]
            lo = lower_bounds.get(f_idx, float("-inf"))
            hi = upper_bounds.get(f_idx, float("inf"))

            if curr_val < lo:
                target_s = lo + _EPSILON
                delta_s = target_s - curr_val
                l2_sum += delta_s ** 2
                leaf_deltas.append((f_idx, target_s, ">", lo))
            elif curr_val > hi:
                target_s = hi - _EPSILON
                delta_s = target_s - curr_val
                l2_sum += delta_s ** 2
                leaf_deltas.append((f_idx, target_s, "<=", hi))

        l2_dist = math.sqrt(l2_sum)
        if l2_dist < min_l2:
            min_l2 = l2_dist
            best_leaf = leaf_id
            best_deltas = leaf_deltas

    if best_leaf is None or not best_deltas:
        return _heuristic_counterfactual(vector, feature_names, target_decision=target_decision, max_features=max_features)

    # Convert best deltas back to unscaled space
    steps: List[CounterfactualStep] = []
    guidance: List[str] = []
    l1_dist = 0.0

    for f_idx, target_s, op, thr_s in best_deltas:
        fname = feature_names[f_idx]
        raw_curr = float(vector[f_idx])

        # Unscale target
        if scales is not None and means is not None:
            raw_target = float(target_s * scales[f_idx] + means[f_idx])
            raw_thr = float(thr_s * scales[f_idx] + means[f_idx])
        else:
            raw_target = float(target_s)
            raw_thr = float(thr_s)

        raw_delta = raw_target - raw_curr
        l1_dist += abs(raw_delta)

        pct_change = (raw_delta / raw_curr * 100.0) if abs(raw_curr) > 1e-6 else 0.0

        if op == "<=":
            action_desc = f"Rate-limit / reduce {fname} to <= {raw_thr:.2f} (change: {raw_delta:+.2f}, {pct_change:+.1f}%)"
        else:
            action_desc = f"Disperse / increase {fname} to > {raw_thr:.2f} (change: {raw_delta:+.2f}, {pct_change:+.1f}%)"

        steps.append(
            CounterfactualStep(
                feature=fname,
                current_value=round(raw_curr, 4),
                target_value=round(raw_target, 4),
                delta=round(raw_delta, 4),
                operator=op,
                threshold=round(raw_thr, 4),
                relative_change_pct=round(pct_change, 2),
                remediation_action=action_desc,
            )
        )
        guidance.append(action_desc)

    steps.sort(key=lambda s: abs(s.relative_change_pct), reverse=True)
    steps = steps[:max_features]

    summary = (
        f"Counterfactual achieved via Decision Tree leaf {best_leaf}: "
        f"{len(steps)} feature change(s) needed to restore {target_decision} (normalized L2: {min_l2:.3f})."
    )

    return CounterfactualExplanation(
        achievable=True,
        target_decision=target_decision,
        required_changes=steps,
        l1_distance=round(l1_dist, 4),
        l2_distance=round(min_l2, 4),
        summary=summary,
        guidance=guidance[:max_features],
    )


def _heuristic_counterfactual(
    vector: Sequence[float],
    feature_names: Sequence[str],
    *,
    target_decision: str = "NORMAL",
    max_features: int = 5,
) -> CounterfactualExplanation:
    """Fallback counterfactual remediation based on static nominal ranges."""
    steps: List[CounterfactualStep] = []
    guidance: List[str] = []
    l1_dist = 0.0
    l2_sum = 0.0

    for i, name in enumerate(feature_names):
        if i >= len(vector):
            break
        lo_hi = NORMAL_RANGES.get(name)
        if not lo_hi:
            continue
        lo, hi = lo_hi
        curr = float(vector[i])

        if curr > hi:
            target = float(hi)
            delta = target - curr
            pct = (delta / curr * 100.0) if abs(curr) > 1e-6 else 0.0
            act = f"Lower {name} from {curr:.2f} to nominal threshold <= {hi:.2f} ({pct:+.1f}%)"
            step = CounterfactualStep(
                feature=name,
                current_value=round(curr, 4),
                target_value=round(target, 4),
                delta=round(delta, 4),
                operator="<=",
                threshold=round(hi, 4),
                relative_change_pct=round(pct, 2),
                remediation_action=act,
            )
            steps.append(step)
            guidance.append(act)
            l1_dist += abs(delta)
            l2_sum += delta ** 2
        elif curr < lo:
            target = float(lo)
            delta = target - curr
            pct = (delta / curr * 100.0) if abs(curr) > 1e-6 else 0.0
            act = f"Restore {name} from {curr:.2f} to nominal floor >= {lo:.2f} ({pct:+.1f}%)"
            step = CounterfactualStep(
                feature=name,
                current_value=round(curr, 4),
                target_value=round(target, 4),
                delta=round(delta, 4),
                operator=">=",
                threshold=round(lo, 4),
                relative_change_pct=round(pct, 2),
                remediation_action=act,
            )
            steps.append(step)
            guidance.append(act)
            l1_dist += abs(delta)
            l2_sum += delta ** 2

    steps.sort(key=lambda s: abs(s.relative_change_pct), reverse=True)
    steps = steps[:max_features]

    achievable = len(steps) > 0
    summary = (
        f"Counterfactual guidance (heuristic): {len(steps)} feature adjustment(s) "
        f"to restore nominal bounds for {target_decision}."
        if achievable
        else f"All features already within nominal baseline bounds for {target_decision}."
    )

    return CounterfactualExplanation(
        achievable=achievable,
        target_decision=target_decision,
        required_changes=steps,
        l1_distance=round(l1_dist, 4),
        l2_distance=round(math.sqrt(l2_sum), 4),
        summary=summary,
        guidance=guidance[:max_features],
    )

