"""
Byzantine-robust federated aggregation strategies.

Supports:
- FedAvg (weighted federated averaging)
- Krum (Blanchard et al., 2017; requires n > 2f + 2)
- Coordinate-wise Trimmed Mean (Yin et al., 2018)
- Robust MAD + Z-score malicious client pre-screening
"""
from __future__ import annotations

import logging
from typing import List, Optional

import numpy as np

logger = logging.getLogger("SecureFL.Aggregation")

ClientWeights = List[np.ndarray]


def _flatten(weights: ClientWeights) -> np.ndarray:
    return np.concatenate([w.astype(np.float64).flatten() for w in weights])


def fedavg(
    weights_list: List[ClientWeights],
    num_samples_list: List[int],
) -> ClientWeights:
    if not weights_list:
        raise ValueError("weights_list is empty")
    if len(weights_list) != len(num_samples_list):
        raise ValueError(
            f"Length mismatch: {len(weights_list)} weight sets vs {len(num_samples_list)} sample counts"
        )
    total_samples = sum(num_samples_list)
    if total_samples <= 0:
        raise ValueError("Total sample count must be > 0")

    reference = weights_list[0]
    num_layers = len(reference)
    aggregated = [np.zeros_like(layer, dtype=np.float64) for layer in reference]

    for client_weights, n_samples in zip(weights_list, num_samples_list):
        if len(client_weights) != num_layers:
            raise ValueError(f"Client weight list has {len(client_weights)} layers; expected {num_layers}")
        fraction = n_samples / total_samples
        for i, layer in enumerate(client_weights):
            aggregated[i] += fraction * layer.astype(np.float64)

    return [arr.astype(reference[i].dtype) for i, arr in enumerate(aggregated)]


def krum(
    weights_list: List[ClientWeights],
    f: int = 1,
) -> ClientWeights:
    n = len(weights_list)
    if n <= 2 * f + 2:
        raise ValueError(
            f"Krum requires n > 2f+2 clients (n={n}, f={f}). Consider >= {2 * f + 3} clients or reducing f."
        )

    flat_weights = np.stack([_flatten(w) for w in weights_list])
    dist_matrix = np.zeros((n, n), dtype=np.float64)
    for i in range(n):
        for j in range(i + 1, n):
            diff = flat_weights[i] - flat_weights[j]
            d2 = float(np.dot(diff, diff))
            dist_matrix[i, j] = d2
            dist_matrix[j, i] = d2

    k = n - f - 2
    scores = np.zeros(n, dtype=np.float64)
    for i in range(n):
        sorted_dists = np.sort(dist_matrix[i])
        scores[i] = sorted_dists[1:k + 1].sum()

    best_idx = int(np.argmin(scores))
    logger.info("krum | n=%d | f=%d | selected_client=%d", n, f, best_idx)
    return weights_list[best_idx]


def trimmed_mean(
    weights_list: List[ClientWeights],
    beta: float = 0.1,
) -> ClientWeights:
    if not (0.0 <= beta < 0.5):
        raise ValueError(f"beta must be in [0, 0.5), got {beta}")
    n = len(weights_list)
    if n == 0:
        raise ValueError("weights_list is empty")

    k_trim = int(n * beta)
    if k_trim == 0 and beta > 0 and n >= 3:
        k_trim = 1
    if 2 * k_trim >= n:
        return fedavg(weights_list, [1] * n)

    reference = weights_list[0]
    aggregated = []
    for layer_idx in range(len(reference)):
        stacked = np.stack([w[layer_idx] for w in weights_list], axis=0)
        sorted_vals = np.sort(stacked, axis=0)
        trimmed = sorted_vals[k_trim:n - k_trim] if k_trim > 0 else sorted_vals
        aggregated.append(trimmed.mean(axis=0).astype(reference[layer_idx].dtype))

    return aggregated


def detect_malicious_clients(
    weights_list: List[ClientWeights],
    threshold: float = 3.0,
) -> List[int]:
    """
    Detect suspected Byzantine clients using Median Absolute Deviation (MAD)
    modified Z-scores on L2 update norms (effective even at n=5 where classical
    std Z-score is mathematically bounded at sqrt(n-1)=2.0).
    """
    n = len(weights_list)
    if n < 3:
        return []

    norms = np.array([np.linalg.norm(_flatten(w)) for w in weights_list], dtype=np.float64)
    med = float(np.median(norms))
    abs_devs = np.abs(norms - med)
    mad = float(np.median(abs_devs))

    if mad > 1e-10:
        mod_z = 0.6745 * abs_devs / mad
        suspected = sorted(int(i) for i in np.where(mod_z > threshold)[0])
        if suspected:
            return suspected

    # Fallback: pairwise median distance outlier check (handles equal-norm sign-flip attacks)
    flat = np.stack([_flatten(w) for w in weights_list])
    med_dists = []
    for i in range(n):
        dists = [np.linalg.norm(flat[i] - flat[j]) for j in range(n) if i != j]
        med_dists.append(float(np.median(dists)))
    dist_arr = np.array(med_dists)
    d_med = float(np.median(dist_arr))
    d_mad = float(np.median(np.abs(dist_arr - d_med)))
    if d_mad > 1e-10:
        d_z = 0.6745 * np.abs(dist_arr - d_med) / d_mad
        return sorted(int(i) for i in np.where(d_z > threshold)[0])

    return []


class RobustAggregator:
    """Unified Byzantine-robust aggregation interface."""

    STRATEGIES = {"fedavg", "krum", "trimmed_mean"}

    def __init__(
        self,
        strategy: str = "fedavg",
        krum_f: int = 1,
        trim_beta: float = 0.1,
        malicious_threshold: float = 3.5,
        auto_detect: bool = True,
    ) -> None:
        self.strategy = strategy.strip().lower()
        if self.strategy not in self.STRATEGIES:
            raise ValueError(f"Unknown strategy '{strategy}'. Choose from {sorted(self.STRATEGIES)}")
        self.krum_f = krum_f
        self.trim_beta = trim_beta
        self.malicious_threshold = malicious_threshold
        self.auto_detect = auto_detect
        self._last_suspicious: List[int] = []

    @property
    def last_suspicious_clients(self) -> List[int]:
        return list(self._last_suspicious)

    def aggregate(
        self,
        weights_list: List[ClientWeights],
        num_samples_list: List[int],
        strategy: Optional[str] = None,
    ) -> ClientWeights:
        chosen = (strategy or self.strategy).strip().lower()
        if chosen not in self.STRATEGIES:
            raise ValueError(f"Unknown strategy '{chosen}'. Choose from {sorted(self.STRATEGIES)}")

        if self.auto_detect:
            self._last_suspicious = detect_malicious_clients(
                weights_list, self.malicious_threshold
            )
            if self._last_suspicious and len(weights_list) - len(self._last_suspicious) >= 2:
                keep = [i for i in range(len(weights_list)) if i not in set(self._last_suspicious)]
                weights_list = [weights_list[i] for i in keep]
                num_samples_list = [num_samples_list[i] for i in keep]
        else:
            self._last_suspicious = []

        if not weights_list:
            raise RuntimeError("All clients excluded; cannot aggregate.")

        if chosen == "fedavg":
            return fedavg(weights_list, num_samples_list)
        if chosen == "krum":
            # If anomaly pre-filter reduced n below 2f+3, adjust f safely or use trimmed_mean
            if len(weights_list) <= 2 * self.krum_f + 2:
                logger.warning(
                    "Post-filter client count %d <= 2*%d+2; falling back to trimmed_mean.",
                    len(weights_list),
                    self.krum_f,
                )
                return trimmed_mean(weights_list, beta=self.trim_beta)
            return krum(weights_list, f=self.krum_f)
        return trimmed_mean(weights_list, beta=self.trim_beta)
