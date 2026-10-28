"""
Isolation Forest Anomaly Explainer (R5 Enhancement).

Explains: "Why did the Isolation Forest score this traffic flow as anomalous?"

Evaluates the feature splits that lead to short path lengths across the isolation ensemble.
Deterministic and lightweight.
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence, Tuple
import numpy as np

from ml_models.explainer import FEATURE_DESCRIPTIONS
from xai.models import AttributionScope, EvidenceKind, FeatureAttribution


def explain_isolation_forest(
    vector: Sequence[float],
    isolation_forest: Any,
    feature_names: Sequence[str],
    *,
    scaler: Any = None,
    top_k: int = 5,
    max_tree_depth_eval: int = 4,
) -> Tuple[List[FeatureAttribution], str]:
    """
    Explain Isolation Forest anomaly assignment by analyzing early split features.

    Returns:
        (attributions, summary_string)
    """
    if isolation_forest is None or not hasattr(isolation_forest, "estimators_"):
        return [], "Isolation Forest explainer unavailable: model missing or not fitted."

    try:
        X = np.asarray([list(vector)], dtype=float)
        if scaler is not None and hasattr(scaler, "transform"):
            X_eval = scaler.transform(X)
        else:
            X_eval = X

        estimators = getattr(isolation_forest, "estimators_", [])
        if not estimators:
            return [], "Isolation Forest has no estimators."

        feature_scores = {name: 0.0 for name in feature_names}

        # Analyze early splits across all trees in the ensemble
        for tree in estimators:
            t = tree.tree_
            node_indicator = tree.decision_path(X_eval)
            nodes = node_indicator.indices[
                node_indicator.indptr[0] : node_indicator.indptr[1]
            ]

            path_length = len(nodes) - 1
            # Anomaly trees are those where sample isolates quickly (short path length)
            # Weight early splits exponentially: 1 / 2^depth
            for depth, node_id in enumerate(nodes[:-1]):
                if depth >= max_tree_depth_eval:
                    break
                f_idx = int(t.feature[node_id])
                if 0 <= f_idx < len(feature_names):
                    fname = feature_names[f_idx]
                    weight = 1.0 / (2.0 ** depth)
                    feature_scores[fname] += weight

        total_score = sum(feature_scores.values())
        if total_score <= 1e-9:
            return [], "Isolation Forest features contributed uniformly."

        # Rank features
        ranked = sorted(feature_scores.items(), key=lambda x: x[1], reverse=True)

        attributions: List[FeatureAttribution] = []
        for name, raw_score in ranked[:top_k]:
            normalized_imp = raw_score / total_score
            f_idx = feature_names.index(name) if name in feature_names else -1
            curr_val = float(vector[f_idx]) if f_idx >= 0 and f_idx < len(vector) else 0.0
            _desc, indicator = FEATURE_DESCRIPTIONS.get(name, ("", ""))

            attributions.append(
                FeatureAttribution(
                    feature=name,
                    value=round(curr_val, 4),
                    importance=round(float(normalized_imp), 4),
                    deviation=f"isolation_weight={normalized_imp * 100:.1f}%",
                    note=f"Early isolation driver: {indicator}",
                    evidence_kind=EvidenceKind.OBSERVED.value,
                    scope=AttributionScope.ISOLATION_CONTRIBUTION.value,
                )
            )

        top_2 = [a.feature for a in attributions[:2]]
        summary = (
            f"Isolation Forest anomaly driven primarily by early splits on {', '.join(top_2)} "
            f"({sum(a.importance or 0 for a in attributions[:2]) * 100:.1f}% combined tree isolation score)."
        )

        return attributions, summary

    except Exception as exc:  # noqa: BLE001
        return [], f"Isolation Forest explanation failed: {exc}"

