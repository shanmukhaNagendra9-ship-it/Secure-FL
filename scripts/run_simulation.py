"""
End-to-End Empirical Simulation & Comparative Evaluation Script.

Executes:
1. 5-Tenant Non-IID Telemetry Generation (tenant_a .. tenant_e)
2. Real PyTorch + Flower FL Training (Krum Byzantine-robust aggregation + RDP DP)
3. Comparative ML Benchmark (LSTM vs. Random Forest vs. XGBoost)
4. Real-Time Inference + SHAP/Gradient XAI Explanation
5. DevSecOps CI/CD Secret/Leakage Gate Verification
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from federated_learning.data_simulator import simulate_all_tenants
from federated_learning.fl_runner import run_federated_training
from federated_learning.ml_benchmark import inference_engine, run_comparative_benchmark
from federated_learning.pipeline_security import PipelineSecurityScanner


def run_experiment() -> None:
    print("=" * 72)
    print(" 1. GENERATING 5-TENANT NON-IID SECURITY TELEMETRY")
    print("=" * 72)
    datasets = simulate_all_tenants(output_dir="data", samples_per_tenant=2500)
    for tid, df in datasets.items():
        print(f"  [OK] {tid}: {len(df)} samples | classes={df['threat_name'].value_counts().to_dict()}")

    print("\n" + "=" * 72)
    print(" 2. RUNNING REAL FLOWER FL (5 CLIENTS + KRUM + RDP DIFFERENTIAL PRIVACY)")
    print("=" * 72)
    fl_summary = run_federated_training(
        rounds=3,
        strategy="krum",
        noise_multiplier=1.2,
        clip_norm=1.0,
        local_epochs=2,
        inject_byzantine=True,
    )
    for r in fl_summary["new_rounds"]:
        print(
            f"  Round {r['round_num']}: Acc={r['accuracy']*100:.2f}% | Loss={r['loss']:.4f} "
            f"| RDP eps={r['privacy_epsilon_spent']:.4f} | Rejected={r['rejected_tenants']}"
        )

    print("\n" + "=" * 72)
    print(" 3. COMPARATIVE ML BENCHMARK (LSTM vs RANDOM FOREST vs XGBOOST)")
    print("=" * 72)
    bench = run_comparative_benchmark(lstm_epochs=5)
    for m in bench["models"]:
        print(
            f"  {m['model_name']:<28} | Acc={m['accuracy']*100:6.2f}% | "
            f"F1={m['f1_score']:.4f} | FPR={m['fpr']*100:5.2f}% | Latency={m['latency_ms']:.4f} ms"
        )

    print("\n" + "=" * 72)
    print(" 4. EXPLAINABLE AI (XAI) REAL-TIME INFERENCE CHECK")
    print("=" * 72)
    xai = inference_engine.analyze(
        {"num_failed_logins": 28, "request_frequency": 210.0, "response_code_status": 1, "is_new_device": 1},
        model_type="lstm",
    )
    print("  Prediction:", xai["threat_type"], "| Severity:", xai["severity"], "| Action:", xai["recommended_action"])
    print("  Explanation:", xai["explanation"])

    print("\n" + "=" * 72)
    print(" 5. DEVSECOPS CROSS-TENANT LEAKAGE & SECRET SCAN CHECK")
    print("=" * 72)
    scanner = PipelineSecurityScanner(tenant_id="tenant_a")
    allowed, msg = scanner.inspect_cross_tenant_leakage("tenant_b", {"query": "SELECT * FROM secrets"})
    print(f"  Cross-Tenant Probe Blocked={not allowed} -> {msg}")
    scan = scanner.scan_source_code("backend")
    print(f"  Backend Secret Scan: {scan['status']} ({scan['scanned_files']} files)")


if __name__ == "__main__":
    run_experiment()
