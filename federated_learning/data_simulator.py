"""
Synthetic Data Simulator for Multi-Tenant Cloud & DevSecOps CI/CD Security Telemetry.

Generates non-IID datasets across 5+ isolated tenant nodes so Krum (n >= 2f + 3)
and cross-tenant federated learning execute authentically.
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional

import numpy as np
import pandas as pd

THREAT_LABELS = {
    0: "normal",
    1: "brute_force",
    2: "data_exfiltration",
    3: "privilege_escalation",
    4: "cross_tenant_leakage",
}

FEATURE_COLUMNS = [
    "num_failed_logins",
    "request_frequency",
    "unusual_access_time",
    "hour_of_day",
    "day_of_week",
    "bytes_transferred_kb",
    "duration_ms",
    "response_code_status",
    "is_vpn",
    "is_new_device",
    "session_duration_sec",
    "repo_commit_rate",
    "file_change_count",
    "vulnerable_deps_count",
    "secret_detection_count",
    "build_failure_count",
    "cross_tenant_access_attempts",
    "suspicious_artifact_activity",
    "privilege_level",
]

TENANT_PROFILES = {
    "tenant_a": ("Tenant Alpha (E-Commerce)", {0: 0.70, 1: 0.18, 2: 0.04, 3: 0.04, 4: 0.04}, 101),
    "tenant_b": ("Tenant Beta (Financial Services)", {0: 0.70, 1: 0.05, 2: 0.14, 3: 0.08, 4: 0.03}, 202),
    "tenant_c": ("Tenant Gamma (Cloud Core & CI/CD)", {0: 0.70, 1: 0.04, 2: 0.04, 3: 0.08, 4: 0.14}, 303),
    "tenant_d": ("Tenant Delta (Healthcare Cloud)", {0: 0.70, 1: 0.08, 2: 0.12, 3: 0.05, 4: 0.05}, 404),
    "tenant_e": ("Tenant Epsilon (SaaS Enterprise)", {0: 0.70, 1: 0.06, 2: 0.05, 3: 0.12, 4: 0.07}, 505),
}


def generate_single_sample(
    tenant_id: str,
    threat_type: int,
    base_time: datetime,
    rng: Optional[random.Random] = None,
) -> Dict[str, float | int | str]:
    r = rng or random.Random()

    hour = r.randint(8, 18)
    day = r.randint(0, 4)
    unusual_time = 0
    failed_logins = r.randint(0, 1)
    freq = round(r.uniform(1.0, 15.0), 2)
    bytes_kb = round(r.uniform(5.0, 500.0), 2)
    duration_ms = round(r.uniform(50.0, 800.0), 2)
    resp_code = 200
    is_vpn = 1 if r.random() < 0.15 else 0
    is_new_device = 1 if r.random() < 0.05 else 0
    session_dur = round(r.uniform(120.0, 3600.0), 1)
    commit_rate = round(r.uniform(0.1, 3.0), 2)
    file_changes = r.randint(1, 20)
    vuln_deps = 0 if r.random() < 0.85 else r.randint(1, 2)
    secrets_found = 0
    build_failures = 0 if r.random() < 0.80 else 1
    cross_tenant_attempts = 0
    artifact_suspicious = 0
    priv_level = r.choice([1, 2])

    if threat_type == 0:
        # Realistic benign edge cases (VPN bulk sync, off-hours jobs, occasional login typo)
        if r.random() < 0.08:
            bytes_kb = round(r.uniform(12000.0, 42000.0), 2)
            unusual_time = 1
            hour = r.choice([2, 3, 22])
            is_vpn = 1
        if r.random() < 0.07:
            failed_logins = r.randint(2, 6)
            freq = round(r.uniform(35.0, 75.0), 2)
    elif threat_type == 1:
        failed_logins = r.randint(4, 35)
        freq = round(r.uniform(40.0, 300.0), 2)
        resp_code = r.choice([401, 403, 429]) if r.random() < 0.92 else 200
        is_new_device = 1 if r.random() < 0.88 else 0
        duration_ms = round(r.uniform(10.0, 180.0), 2)
    elif threat_type == 2:
        bytes_kb = round(r.uniform(14000.0, 250000.0), 2)
        session_dur = round(r.uniform(2400.0, 14400.0), 1)
        unusual_time = 1 if r.random() < 0.72 else 0
        hour = r.choice([1, 2, 3, 4, 23]) if unusual_time else r.randint(9, 17)
        is_vpn = 1 if r.random() < 0.85 else 0
        freq = round(r.uniform(25.0, 120.0), 2)
    elif threat_type == 3:
        priv_level = 3 if r.random() < 0.90 else 2
        secrets_found = r.randint(0, 6)
        vuln_deps = r.randint(1, 8)
        build_failures = r.randint(1, 7)
        file_changes = r.randint(25, 200)
        commit_rate = round(r.uniform(3.5, 18.0), 2)
    elif threat_type == 4:
        cross_tenant_attempts = r.randint(1, 12)
        resp_code = 403 if r.random() < 0.90 else 200
        artifact_suspicious = 1 if r.random() < 0.85 else 0
        is_new_device = 1 if r.random() < 0.80 else 0
        unusual_time = 1 if r.random() < 0.78 else 0
        hour = r.choice([0, 1, 2, 22, 23])
        failed_logins = r.randint(1, 8)

    return {
        "event_id": f"evt-{r.randint(10000000, 99999999)}",
        "timestamp": (base_time + timedelta(seconds=r.randint(0, 86400 * 30))).isoformat(),
        "tenant_id": tenant_id,
        "source_ip": f"10.{r.randint(1, 254)}.{r.randint(1, 254)}.{r.randint(1, 254)}",
        "num_failed_logins": failed_logins,
        "request_frequency": freq,
        "unusual_access_time": unusual_time,
        "hour_of_day": hour,
        "day_of_week": day,
        "bytes_transferred_kb": bytes_kb,
        "duration_ms": duration_ms,
        "response_code_status": 1 if resp_code in (401, 403, 429, 500) else 0,
        "is_vpn": is_vpn,
        "is_new_device": is_new_device,
        "session_duration_sec": session_dur,
        "repo_commit_rate": commit_rate,
        "file_change_count": file_changes,
        "vulnerable_deps_count": vuln_deps,
        "secret_detection_count": secrets_found,
        "build_failure_count": build_failures,
        "cross_tenant_access_attempts": cross_tenant_attempts,
        "suspicious_artifact_activity": artifact_suspicious,
        "privilege_level": priv_level,
        "label": threat_type,
        "threat_name": THREAT_LABELS[threat_type],
    }


def generate_tenant_dataset(
    tenant_id: str,
    num_samples: int = 3000,
    threat_ratios: Optional[Dict[int, float]] = None,
    seed: int = 42,
) -> pd.DataFrame:
    np_rng = np.random.default_rng(seed)
    py_rng = random.Random(seed)

    if threat_ratios is None:
        threat_ratios = {0: 0.72, 1: 0.10, 2: 0.07, 3: 0.06, 4: 0.05}

    base_time = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    threat_types = list(threat_ratios.keys())
    probs = np.array(list(threat_ratios.values()), dtype=np.float64)
    probs /= probs.sum()

    chosen_threats = np_rng.choice(threat_types, size=num_samples, p=probs)
    records = [generate_single_sample(tenant_id, int(t), base_time, py_rng) for t in chosen_threats]
    return pd.DataFrame(records)


def simulate_all_tenants(
    output_dir: str = "data",
    samples_per_tenant: int = 3000,
) -> Dict[str, pd.DataFrame]:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    datasets: Dict[str, pd.DataFrame] = {}

    for t_id, (_name, ratios, seed) in TENANT_PROFILES.items():
        t_dir = path / t_id
        t_dir.mkdir(parents=True, exist_ok=True)
        df = generate_tenant_dataset(
            t_id, num_samples=samples_per_tenant, threat_ratios=ratios, seed=seed
        )
        df.to_csv(t_dir / "logs.csv", index=False)
        datasets[t_id] = df

    return datasets


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Tenant 5-Node Telemetry Simulator")
    parser.add_argument("--samples", type=int, default=3000)
    parser.add_argument("--outdir", type=str, default="data")
    args = parser.parse_args()
    ds = simulate_all_tenants(output_dir=args.outdir, samples_per_tenant=args.samples)
    print(f"Generated datasets for {len(ds)} tenants ({list(ds.keys())}).")
