"""
IntelliShield XAI package (Requirement R5).

R5.1: Prediction explanation core (native Decision Tree path + evidence tagging).
R5.2: RootCauseEngine lives in sibling package ``rca/`` (not here).
"""

from xai.config import XAIConfig
from xai.counterfactual import compute_counterfactual
from xai.engine import XAIEngine
from xai.faithfulness import faithfulness_rate, verify_path_against_model
from xai.isolation_explainer import explain_isolation_forest
from xai.reconstruction_explainer import explain_reconstruction_error
from xai.models import (
    AttributionScope,
    CounterfactualExplanation,
    CounterfactualStep,
    DecisionPathStep,
    EvidenceKind,
    ExplanationMethod,
    ExplanationStatus,
    FeatureAttribution,
    PredictionExplanation,
)
from xai.legacy_bridge import explanation_to_legacy_dict
from ml_models.explainer import FEATURE_DESCRIPTIONS, NORMAL_RANGES

__all__ = [
    "AttributionScope",
    "CounterfactualExplanation",
    "CounterfactualStep",
    "FEATURE_DESCRIPTIONS",
    "NORMAL_RANGES",
    "XAIConfig",
    "XAIEngine",
    "DecisionPathStep",
    "EvidenceKind",
    "ExplanationMethod",
    "ExplanationStatus",
    "FeatureAttribution",
    "PredictionExplanation",
    "compute_counterfactual",
    "explain_isolation_forest",
    "explain_reconstruction_error",
    "explanation_to_legacy_dict",
    "faithfulness_rate",
    "verify_path_against_model",
]
