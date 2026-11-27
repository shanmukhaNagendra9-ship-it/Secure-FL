"""
SecureFL Federated Learning Modules.
"""
from federated_learning.model import AutoencoderDetector, LSTMThreatDetector, ThreatLabel, get_model
from federated_learning.aggregation import RobustAggregator, detect_malicious_clients, fedavg, krum, trimmed_mean
from federated_learning.privacy import (
    GaussianMechanism,
    PairwiseSecureAggregator,
    PrivacyAccountant,
    RDPPrivacyAccountant,
    SecureAggregator,
    clip_update_ndarrays,
    gradient_clip,
)

__all__ = [
    "AutoencoderDetector",
    "GaussianMechanism",
    "LSTMThreatDetector",
    "PairwiseSecureAggregator",
    "PrivacyAccountant",
    "RDPPrivacyAccountant",
    "RobustAggregator",
    "SecureAggregator",
    "ThreatLabel",
    "clip_update_ndarrays",
    "detect_malicious_clients",
    "fedavg",
    "get_model",
    "gradient_clip",
    "krum",
    "trimmed_mean",
]
