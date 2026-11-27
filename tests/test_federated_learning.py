"""
Real Federated Learning, RDP Differential Privacy, Byzantine Aggregation, & Secure Aggregation Tests.
(Zero stub implementations; directly tests federated_learning/* production modules.)
"""
from __future__ import annotations

import numpy as np
import pytest
import torch

from federated_learning.aggregation import (
    RobustAggregator,
    detect_malicious_clients,
    krum,
    trimmed_mean,
)
from federated_learning.data_simulator import FEATURE_COLUMNS, TENANT_PROFILES, simulate_all_tenants
from federated_learning.fl_runner import run_federated_training
from federated_learning.model import AutoencoderDetector, LSTMThreatDetector
from federated_learning.privacy import (
    GaussianMechanism,
    PairwiseSecureAggregator,
    RDPPrivacyAccountant,
    clip_update_ndarrays,
    gradient_clip,
)


def test_lstm_and_autoencoder_19_features():
    assert len(FEATURE_COLUMNS) == 19
    lstm = LSTMThreatDetector()
    assert lstm.input_size == 19
    x = torch.randn(8, 1, 19)
    logits = lstm(x)
    assert logits.shape == (8, 5)

    ae = AutoencoderDetector()
    assert ae.input_size == 19
    z_scored_x = torch.randn(8, 19) * 2.0  # includes negative & >1 values
    x_hat, z = ae(z_scored_x)
    assert x_hat.shape == (8, 1, 19)
    assert z.shape == (8, 8)
    scores = ae.anomaly_score(z_scored_x)
    assert scores.shape == (8,)
    assert torch.all(scores >= 0)


def test_rdp_privacy_accountant_and_gaussian_noise():
    gm = GaussianMechanism()
    t = torch.zeros(64)
    noisy = gm.add_noise_with_multiplier(t, sensitivity=1.0, noise_multiplier=1.2)
    assert not torch.allclose(t, noisy)

    acct = RDPPrivacyAccountant(total_epsilon=2.0, total_delta=1e-5)
    rec1 = acct.step_rdp(noise_multiplier=1.2, sample_rate=0.05, steps=2)
    rec2 = acct.step_rdp(noise_multiplier=1.2, sample_rate=0.05, steps=2)
    assert rec1["round_epsilon"] > 0
    assert rec2["cumulative_epsilon"] > rec1["cumulative_epsilon"]
    assert acct.spent_epsilon == acct.epsilon_spent

    acct_small = RDPPrivacyAccountant(total_epsilon=1.0, total_delta=1e-5)
    acct_small.spend(1.5, 1e-6)
    assert acct_small.is_budget_exceeded() is True
    with pytest.raises(RuntimeError):
        acct_small.spend(0.2, 1e-6)


def test_gradient_and_update_clipping():
    p = torch.nn.Parameter(torch.ones(10))
    (p * 20.0).sum().backward()
    raw_norm = gradient_clip([p], max_norm=1.0)
    assert raw_norm > 1.0
    assert torch.norm(p.grad).item() <= 1.0 + 1e-5

    clipped, norm_before = clip_update_ndarrays([np.ones(100, dtype=np.float32) * 5.0], max_norm=1.0)
    assert norm_before > 1.0
    assert np.linalg.norm(clipped[0]) <= 1.0 + 1e-5


def test_krum_trimmed_mean_and_byzantine_detection():
    rng = np.random.default_rng(7)
    honest = [[rng.normal(0.0, 0.1, size=32).astype(np.float32)] for _ in range(4)]
    byzantine = [[rng.normal(50.0, 1.0, size=32).astype(np.float32)]]
    all_w = honest + byzantine

    suspects = detect_malicious_clients(all_w, threshold=3.0)
    assert 4 in suspects

    selected = krum(all_w, f=1)
    assert np.linalg.norm(selected[0]) < 5.0

    tm = trimmed_mean(all_w, beta=0.2)
    assert np.linalg.norm(tm[0]) < 5.0

    agg = RobustAggregator(strategy="krum", krum_f=1, auto_detect=True)
    res = agg.aggregate(all_w, [100] * 5)
    assert 4 in agg.last_suspicious_clients
    assert np.linalg.norm(res[0]) < 5.0


def test_pairwise_x25519_secure_aggregation_exact_cancellation():
    sa = PairwiseSecureAggregator()
    cids = ["tenant_a", "tenant_b", "tenant_c"]
    pubs = {cid: sa.register_client(cid) for cid in cids}

    updates = {
        "tenant_a": [np.array([1.0, 2.0, 3.0], dtype=np.float32)],
        "tenant_b": [np.array([4.0, 5.0, 6.0], dtype=np.float32)],
        "tenant_c": [np.array([7.0, 8.0, 9.0], dtype=np.float32)],
    }
    masked = [sa.mask_client_update(cid, updates[cid], pubs, round_num=1) for cid in cids]
    # Individual masked updates must differ significantly from raw updates
    assert not np.allclose(masked[0][0], updates["tenant_a"][0])

    agg = sa.aggregate_masked_updates(masked)
    expected_mean = np.array([4.0, 5.0, 6.0], dtype=np.float32)
    assert np.allclose(agg[0], expected_mean, atol=1e-5)


def test_five_tenant_simulator_and_real_fl_runner(tmp_path):
    assert len(TENANT_PROFILES) >= 5
    ds = simulate_all_tenants(output_dir=str(tmp_path / "data"), samples_per_tenant=300)
    assert len(ds) == 5

    summary = run_federated_training(
        rounds=2,
        strategy="krum",
        noise_multiplier=1.2,
        local_epochs=1,
        inject_byzantine=True,
        data_dir=str(tmp_path / "data"),
        models_dir=str(tmp_path / "models"),
        metrics_path=str(tmp_path / "metrics.json"),
    )
    assert summary["total_rounds_completed"] == 2
    assert summary["privacy_epsilon_total"] > 0
    assert "tenant_e" in summary["new_rounds"][0]["rejected_tenants"]
