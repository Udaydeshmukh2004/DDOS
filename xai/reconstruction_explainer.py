"""
Autoencoder Reconstruction Error Explainer (R5 Enhancement).

Provides feature-wise reconstruction error attribution for Self-Supervised
Zero-Day (SSL) anomaly detection and autoencoders.

Explains: "Which feature dimensions failed reconstruction, causing the zero-day alert?"
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence, Tuple
import numpy as np

from ml_models.explainer import FEATURE_DESCRIPTIONS
from xai.models import AttributionScope, EvidenceKind, FeatureAttribution


def explain_reconstruction_error(
    vector: Sequence[float],
    autoencoder: Any,
    feature_names: Sequence[str],
    *,
    top_k: int = 5,
) -> Tuple[List[FeatureAttribution], float, str]:
    """
    Compute feature-wise reconstruction error attributions.

    Returns:
        (attributions, total_mse, narrative_summary)
    """
    if autoencoder is None or not hasattr(autoencoder, "reconstruct"):
        # Check for sklearn-like predict / MLPRegressor
        if not hasattr(autoencoder, "predict"):
            return [], 0.0, "Reconstruction explainer unavailable: autoencoder not fitted."

    try:
        X = np.asarray([list(vector)], dtype=float)
        if hasattr(autoencoder, "reconstruct"):
            X_recon = autoencoder.reconstruct(X)
        else:
            X_recon = autoencoder.predict(X)

        if isinstance(X_recon, list):
            X_recon = np.asarray(X_recon, dtype=float)

        x_orig = X[0]
        x_hat = X_recon[0]

        # Element-wise squared errors
        sq_errors = (x_orig - x_hat) ** 2
        total_se = float(np.sum(sq_errors))
        total_mse = float(np.mean(sq_errors))

        if total_se < 1e-12:
            return [], total_mse, "Reconstruction error negligible; traffic matches normal latent manifold."

        # Compute relative percentage contributions
        contributions = sq_errors / total_se

        attributions: List[FeatureAttribution] = []
        indexed_errors = sorted(
            enumerate(contributions),
            key=lambda item: item[1],
            reverse=True,
        )

        for idx, contrib in indexed_errors[:top_k]:
            fname = feature_names[idx] if idx < len(feature_names) else f"feature_{idx}"
            err_val = float(sq_errors[idx])
            curr_val = float(x_orig[idx])
            _desc, indicator = FEATURE_DESCRIPTIONS.get(fname, ("", ""))

            attributions.append(
                FeatureAttribution(
                    feature=fname,
                    value=round(curr_val, 4),
                    importance=round(float(contrib), 4),
                    deviation=f"error={err_val:.3f} ({contrib * 100:.1f}% of total anomaly energy)",
                    note=f"Reconstruction failure: {indicator}",
                    evidence_kind=EvidenceKind.OBSERVED.value,
                    scope=AttributionScope.RECONSTRUCTION_ERROR.value,
                )
            )

        top_names = [a.feature for a in attributions[:2]]
        summary = (
            f"Zero-Day Autoencoder MSE: {total_mse:.4f}. "
            f"Anomaly predominantly driven by {', '.join(top_names)} "
            f"({sum(a.importance or 0 for a in attributions[:2]) * 100:.1f}% combined error contribution)."
        )

        return attributions, total_mse, summary

    except Exception as exc:  # noqa: BLE001
        return [], 0.0, f"Reconstruction explanation failed: {exc}"

