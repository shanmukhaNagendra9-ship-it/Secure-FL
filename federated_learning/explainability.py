"""
Explainable AI (XAI) Engine for Multi-Tenant Threat Detection.

Computes per-event feature attributions (SHAP TreeExplainer for tree models,
PyTorch input-gradient attributions for LSTM, and standardized feature deviations),
producing human-readable threat explanations and recommended response actions.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import numpy as np

from .data_simulator import FEATURE_COLUMNS, THREAT_LABELS

logger = logging.getLogger("SecureFL.XAI")

RECOMMENDED_ACTIONS = {
    "normal": "monitor_only",
    "brute_force": "restrict_account",
    "data_exfiltration": "revoke_session",
    "privilege_escalation": "restrict_account",
    "cross_tenant_leakage": "block_ip",
}

FEATURE_DESCRIPTIONS = {
    "num_failed_logins": "Failed authentication attempts",
    "request_frequency": "API request burst rate (/min)",
    "unusual_access_time": "Off-hours access flag",
    "hour_of_day": "Access hour (UTC)",
    "day_of_week": "Day of week",
    "bytes_transferred_kb": "Outbound payload volume (KB)",
    "duration_ms": "Request latency (ms)",
    "response_code_status": "HTTP 401/403/429 error indicator",
    "is_vpn": "VPN tunnel usage",
    "is_new_device": "Unrecognized client device",
    "session_duration_sec": "Session duration (sec)",
    "repo_commit_rate": "CI/CD repository commit velocity",
    "file_change_count": "Modified repository files",
    "vulnerable_deps_count": "Known vulnerable dependencies",
    "secret_detection_count": "Exposed secrets detected",  # pragma: allowlist secret
    "build_failure_count": "Consecutive CI build failures",
    "cross_tenant_access_attempts": "Cross-tenant boundary probe count",
    "suspicious_artifact_activity": "Suspicious build artifact access",
    "privilege_level": "Requested IAM privilege tier",
}


class ThreatExplainer:
    """Produces SHAP / gradient-based explanations for ML threat predictions."""

    @staticmethod
    def _normalize_importances(raw: np.ndarray) -> np.ndarray:
        abs_vals = np.abs(raw.astype(np.float64))
        total = float(abs_vals.sum())
        if total <= 1e-12:
            return np.zeros_like(abs_vals)
        return abs_vals / total

    def explain_event(
        self,
        raw_features: List[float],
        scaled_features: np.ndarray,
        predicted_class: int,
        confidence: float,
        anomaly_score: float,
        model_type: str = "lstm",
        torch_model: Optional[Any] = None,
        tree_model: Optional[Any] = None,
    ) -> Dict[str, Any]:
        threat_key = THREAT_LABELS.get(predicted_class, "unknown")
        severity = (
            "low"
            if predicted_class == 0
            else ("critical" if confidence >= 0.88 or anomaly_score >= 2.5 else ("high" if confidence >= 0.7 else "medium"))
        )

        attribution_method = "zscore_sensitivity"
        attributions = np.abs(scaled_features.flatten())

        # 1. PyTorch LSTM Gradient * Input Attribution
        if model_type == "lstm" and torch_model is not None:
            try:
                import torch
                torch_model.eval()
                x_t = torch.tensor(scaled_features, dtype=torch.float32).reshape(1, 1, -1)
                x_t.requires_grad_(True)
                logits = torch_model(x_t)
                score = logits[0, predicted_class]
                torch_model.zero_grad()
                score.backward()
                grad = x_t.grad.detach().numpy().flatten()
                attributions = np.abs(grad * scaled_features.flatten())
                attribution_method = "lstm_gradient_x_input"
            except Exception as exc:
                logger.debug("LSTM gradient attribution fallback: %s", exc)

        # 2. SHAP TreeExplainer for Random Forest / XGBoost
        elif model_type in ("random_forest", "xgboost") and tree_model is not None:
            try:
                import shap
                explainer = shap.TreeExplainer(tree_model)
                shap_vals = explainer.shap_values(scaled_features.reshape(1, -1))
                if isinstance(shap_vals, list):
                    vec = np.asarray(shap_vals[predicted_class]).flatten()
                elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
                    vec = shap_vals[0, :, predicted_class].flatten()
                else:
                    vec = np.asarray(shap_vals).flatten()
                if len(vec) == len(FEATURE_COLUMNS):
                    attributions = np.abs(vec)
                    attribution_method = "shap_tree_explainer"
            except Exception as exc:
                logger.debug("SHAP TreeExplainer fallback: %s", exc)

        weights = self._normalize_importances(attributions)
        top_indices = np.argsort(weights)[::-1][:5]

        top_features = []
        for idx in top_indices:
            fname = FEATURE_COLUMNS[int(idx)]
            top_features.append(
                {
                    "feature": fname,
                    "label": FEATURE_DESCRIPTIONS.get(fname, fname),
                    "value": round(float(raw_features[int(idx)]), 3),
                    "impact": round(float(weights[int(idx)]), 4),
                }
            )

        driver_str = ", ".join(
            f"{f['label']}={f['value']} ({f['impact']*100:.1f}%)" for f in top_features[:3]
        )
        explanation = (
            f"Classified as {threat_key.replace('_', ' ').title()} ({confidence*100:.1f}% confidence, "
            f"anomaly score {anomaly_score:.3f}) via {attribution_method}. "
            f"Primary risk drivers: {driver_str}."
        )

        return {
            "threat_label": threat_key,
            "severity": severity,
            "confidence": round(float(confidence), 4),
            "anomaly_score": round(float(anomaly_score), 4),
            "model_used": model_type,
            "attribution_method": attribution_method,
            "top_features": top_features,
            "explanation": explanation,
            "recommended_action": RECOMMENDED_ACTIONS.get(threat_key, "notify_admin"),
        }


threat_explainer = ThreatExplainer()
