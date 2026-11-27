# Comparative Research & Empirical Evaluation — SecureFL v3.0.0

**Evaluation Script:** `scripts/run_simulation.py`  
**Dataset:** 5-Tenant Non-IID Synthetic Cloud & CI/CD Telemetry (`data/tenant_{a,b,c,d,e}/logs.csv`, 2,500 samples per tenant = 12,500 total events across 19 engineered features and 5 threat classes).  
**Environment:** Local Python 3.11.9 CPU execution (`torch==2.15.0+cpu`, `flwr==1.40.0`, `xgboost==3.2.0`, `scikit-learn==1.9.1`).

---

## 1. Multi-Tenant Non-IID Class Distribution (`2,500` samples/tenant)

| Tenant Node | Normal | Brute Force | Data Exfiltration | Privilege Escalation | Cross-Tenant Leakage |
|---|---|---|---|---|---|
| `tenant_a` (Alpha E-Commerce) | 1,745 | **437** | 112 | 96 | 110 |
| `tenant_b` (Beta Financial) | 1,768 | 122 | **333** | 213 | 64 |
| `tenant_c` (Gamma Cloud/CI-CD) | 1,805 | 87 | 97 | 188 | **323** |
| `tenant_d` (Delta Healthcare) | 1,708 | 200 | **322** | 146 | 124 |
| `tenant_e` (Epsilon SaaS) | 1,750 | 151 | 135 | **284** | 180 |

---

## 2. Flower Federated Learning + Krum + RDP Differential Privacy

Executed via `run_federated_training(rounds=3, strategy="krum", noise_multiplier=1.2, clip_norm=1.0, local_epochs=2, inject_byzantine=True)` with `tenant_e` acting as a synthetic poisoning adversary (`weights * -12.0`).

| FL Round | Strategy | Global Eval Accuracy | Global Eval Loss | Cumulative RDP $\varepsilon$ ($\delta = 10^{-5}$) | Byzantine Clients Rejected |
|---|---|---|---|---|---|
| **Round 1** | Krum / Post-Filter | **88.13%** | 0.5012 | **1.3061** | `['tenant_e']` |
| **Round 2** | Krum / Post-Filter | **97.33%** | 0.1017 | **1.3329** | `['tenant_e']` |
| **Round 3** | Krum / Post-Filter | **99.27%** | 0.0238 | **1.3598** | `['tenant_e']` |

**Key Observations:**
1. **Byzantine Defense:** MAD modified Z-score outlier screening (`detect_malicious_clients`) rejected `tenant_e` in every round while preserving model convergence from `88.13%` to `99.27%`.
2. **Subsampled RDP Composition:** Cumulative privacy loss increased sublinearly by `+0.0268`–`+0.0269` $\varepsilon$ per round (`1.3061 -> 1.3329 -> 1.3598`), well below the `10.0` budget cap.
3. **Cryptographic Pairwise Secure Aggregation:** Ephemeral X25519 ECDH + HKDF pairwise additive masks (`PairwiseSecureAggregator`) verified exact algebraic cancellation ($\text{atol} < 10^{-5}$) in unit tests without sharing static seeds with the coordinator.

---

## 3. Comparative ML Model Benchmark (`test_samples = 3,125`)

Recorded from `run_comparative_benchmark()` (`metrics/model_benchmarks.json` / `scripts/run_simulation.py`):

| Model | Scope | Accuracy | Precision | Recall | F1-Score | FPR | Inference Latency (ms/sample) |
|---|---|---|---|---|---|---|---|
| **Random Forest** | Centralized Benchmark | **100.00%** | 1.0000 | 1.0000 | 1.0000 | 0.00% | 0.0095–0.0140 ms |
| **XGBoost** | Centralized Benchmark | **99.97%** | 0.9997 | 0.9997 | 0.9997 | 0.05% | 0.0016–0.0020 ms |
| **LSTM (PyTorch)** | Federated / Sequential | **99.74%–99.84%** | 0.9974–0.9984 | 0.9974–0.9984 | 0.9974–0.9984 | 0.18%–0.36% | 0.0018–0.0029 ms |

*(Note: Centralized tree models serve as non-private upper-bound baselines; the Federated LSTM achieves ~99.7%–99.8% accuracy and ~0.002–0.003 ms inference latency **without** centralizing raw tenant telemetry logs.)*

---

## 4. Explainable AI (XAI) Sample Evaluation

- **Test Event:** Brute-force burst (`num_failed_logins=28`, `request_frequency=210.0`, `response_code_status=1`, `is_new_device=1`).
- **Model Output:** `Brute Force` | Confidence: **99.7%** | Autoencoder Anomaly Score: **1.547** | Severity: **critical** | Recommended Action: `restrict_account`.
- **Top Attributions (`lstm_gradient_x_input`):**
  1. `num_failed_logins` (`28.0`) — **41.9%** attribution weight
  2. `response_code_status` (`1.0`) — **15.0%** attribution weight
  3. `unusual_access_time` (`0.0`) — **6.9%** attribution weight
