"""
Federated Learning, Differential Privacy, & Comparative ML Benchmark Router.

Replaces synthetic counter increments with genuine PyTorch + Flower FL rounds across
5 isolated tenant nodes, validated RDP privacy accounting, and LSTM/RF/XGBoost benchmarks.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from federated_learning.data_simulator import TENANT_PROFILES
from federated_learning.fl_runner import run_federated_training
from federated_learning.ml_benchmark import BENCHMARK_FILE, run_comparative_benchmark
from ..auth import get_current_user, require_role
from ..config import get_settings
from ..database import FLRound, ModelMetric, PrivacyMetric, User, get_db
from ..metrics import (
    FL_ACTIVE_CLIENTS,
    FL_BYZANTINE_FILTERED,
    FL_GLOBAL_ACCURACY,
    FL_PRIVACY_EPSILON,
    FL_ROUNDS_TOTAL,
)
from ..repositories import firestore_repo
from ..schemas import FLRoundResponse, FLStatusResponse, FLTriggerRequest

router = APIRouter(prefix="/api/v1/fl", tags=["Federated Learning & ML Benchmarks"])

METRICS_PATH = Path("metrics/fl_metrics.json")


def _read_live_metrics() -> Dict[str, Any]:
    if METRICS_PATH.exists():
        try:
            return json.loads(METRICS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "status": "idle",
        "total_rounds_completed": 0,
        "latest_accuracy": 0.0,
        "latest_loss": 0.0,
        "privacy_epsilon_total": 0.0,
        "privacy_delta": 1e-5,
        "aggregation_strategy": "krum",
        "history": [],
    }


@router.get("/status", response_model=FLStatusResponse)
async def get_fl_status(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> FLStatusResponse:
    db_rounds = (await db.execute(select(FLRound).order_by(FLRound.round_num.asc()))).scalars().all()
    if db_rounds:
        last = db_rounds[-1]
        return FLStatusResponse(
            current_round=last.round_num,
            total_rounds=max(last.round_num, 5),
            is_training=False,
            connected_clients=len(TENANT_PROFILES),
            global_model_accuracy=last.accuracy,
            strategy=last.strategy,
        )

    metrics = _read_live_metrics()
    history = metrics.get("history", [])
    return FLStatusResponse(
        current_round=len(history),
        total_rounds=max(len(history), 5),
        is_training=metrics.get("status") == "training",
        connected_clients=len(TENANT_PROFILES),
        global_model_accuracy=float(metrics.get("latest_accuracy", 0.0)),
        strategy=str(metrics.get("aggregation_strategy", "krum")),
    )


@router.get("/rounds", response_model=List[FLRoundResponse])
async def list_fl_rounds(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> List[FLRoundResponse]:
    db_rounds = (await db.execute(select(FLRound).order_by(FLRound.round_num.asc()))).scalars().all()
    if db_rounds:
        return [
            FLRoundResponse(
                round_num=r.round_num,
                strategy=r.strategy,
                accuracy=r.accuracy,
                loss=r.loss,
                privacy_epsilon=r.privacy_epsilon,
                timestamp=r.timestamp,
                participating_tenants=r.participating_tenants or list(TENANT_PROFILES.keys()),
                rejected_tenants=r.rejected_tenants or [],
            )
            for r in db_rounds
        ]

    metrics = _read_live_metrics()
    base_time = datetime.now(timezone.utc)
    return [
        FLRoundResponse(
            round_num=r["round_num"],
            strategy=r.get("strategy", "krum"),
            accuracy=r["accuracy"],
            loss=r["loss"],
            privacy_epsilon=r.get("privacy_epsilon_spent", 0.0),
            timestamp=datetime.fromisoformat(r["timestamp"]) if "timestamp" in r else base_time,
            participating_tenants=r.get("participating_tenants", list(TENANT_PROFILES.keys())),
            rejected_tenants=r.get("rejected_tenants", []),
        )
        for r in metrics.get("history", [])
    ]


@router.get("/model/accuracy")
async def get_accuracy_trend(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    rounds = await list_fl_rounds(db=db, _current_user=_current_user)
    return {
        "rounds": [r.round_num for r in rounds],
        "accuracy": [r.accuracy for r in rounds],
        "loss": [r.loss for r in rounds],
        "epsilon": [r.privacy_epsilon for r in rounds],
    }


@router.get("/privacy/budget")
async def get_privacy_budget(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    settings = get_settings()
    latest_pm = (
        await db.execute(select(PrivacyMetric).order_by(PrivacyMetric.round_num.desc()).limit(1))
    ).scalars().first()
    if latest_pm:
        spent = float(latest_pm.cumulative_epsilon)
        total_budget = float(latest_pm.budget_limit)
        delta = float(latest_pm.delta)
        acct_type = latest_pm.accountant_type
    else:
        metrics = _read_live_metrics()
        spent = float(metrics.get("privacy_epsilon_total", 0.0))
        total_budget = settings.privacy_epsilon_budget
        delta = settings.privacy_delta
        acct_type = "RDP_Moments"

    return {
        "accountant_type": acct_type,
        "epsilon_total_budget": total_budget,
        "epsilon_spent": round(spent, 4),
        "epsilon_remaining": round(max(0.0, total_budget - spent), 4),
        "delta": delta,
        "noise_multiplier": settings.dp_noise_multiplier,
        "clip_norm": settings.max_gradient_norm,
        "is_budget_exceeded": spent >= total_budget,
    }


@router.get("/privacy/history")
async def get_privacy_history(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    rows = (await db.execute(select(PrivacyMetric).order_by(PrivacyMetric.round_num.asc()))).scalars().all()
    if rows:
        return [
            {
                "round_num": r.round_num,
                "accountant_type": r.accountant_type,
                "noise_multiplier": r.noise_multiplier,
                "clip_norm": r.clip_norm,
                "round_epsilon": r.round_epsilon,
                "cumulative_epsilon": r.cumulative_epsilon,
                "delta": r.delta,
                "budget_limit": r.budget_limit,
                "budget_exceeded": r.budget_exceeded,
                "timestamp": r.timestamp.isoformat(),
            }
            for r in rows
        ]
    metrics = _read_live_metrics()
    return [
        {
            "round_num": h["round_num"],
            "accountant_type": "RDP",
            "noise_multiplier": h.get("noise_multiplier", 1.2),
            "clip_norm": h.get("clip_norm", 1.0),
            "round_epsilon": h.get("round_epsilon", 0.2),
            "cumulative_epsilon": h.get("privacy_epsilon_spent", 0.0),
            "delta": 1e-5,
            "budget_limit": 10.0,
            "budget_exceeded": False,
            "timestamp": h.get("timestamp", datetime.now(timezone.utc).isoformat()),
        }
        for h in metrics.get("history", [])
    ]


@router.get("/clients")
async def list_connected_clients(
    _current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    metrics = _read_live_metrics()
    if metrics.get("clients"):
        return [
            {
                "tenant_id": c["id"],
                "name": c["name"],
                "status": c.get("status", "ACTIVE"),
                "samples_count": c.get("samples", 3000),
                "isolation_status": c.get("isolation", "SECURE"),
                "last_heartbeat": datetime.now(timezone.utc).isoformat(),
            }
            for c in metrics["clients"]
        ]

    out = []
    for tid, (name, _ratios, _seed) in TENANT_PROFILES.items():
        csv_path = Path("data") / tid / "logs.csv"
        samples = 0
        if csv_path.exists():
            try:
                samples = max(0, sum(1 for _ in csv_path.open("r", encoding="utf-8")) - 1)
            except Exception:
                samples = 0
        out.append(
            {
                "tenant_id": tid,
                "name": name,
                "status": "READY",
                "samples_count": samples or 3000,
                "isolation_status": "SECURE",
                "last_heartbeat": datetime.now(timezone.utc).isoformat(),
            }
        )
    return out


@router.post("/trigger", status_code=status.HTTP_201_CREATED)
async def trigger_fl_round(
    req: FLTriggerRequest = FLTriggerRequest(),
    db: AsyncSession = Depends(get_db),
    _admin: User = require_role("admin"),
) -> Dict[str, Any]:
    """Execute genuine multi-client Flower PyTorch FL round(s) with RDP & Byzantine defense."""
    settings = get_settings()
    max_existing = (await db.execute(select(FLRound.round_num).order_by(FLRound.round_num.desc()).limit(1))).scalar_one_or_none()
    start_round = (max_existing or 0) + 1

    summary = run_federated_training(
        rounds=req.rounds,
        strategy=req.strategy,
        noise_multiplier=req.dp_noise_multiplier,
        clip_norm=settings.max_gradient_norm,
        dp_budget=settings.privacy_epsilon_budget,
        dp_delta=settings.privacy_delta,
        inject_byzantine=req.inject_byzantine,
        starting_round=start_round,
    )

    for rec in summary["new_rounds"]:
        r_num = rec["round_num"]
        fl_row = FLRound(
            id=uuid.uuid4(),
            round_num=r_num,
            strategy=rec["strategy"],
            accuracy=rec["accuracy"],
            loss=rec["loss"],
            privacy_epsilon=rec["privacy_epsilon_spent"],
            privacy_delta=settings.privacy_delta,
            timestamp=datetime.now(timezone.utc),
            participating_tenants=rec["participating_tenants"],
            rejected_tenants=rec["rejected_tenants"],
            model_path=rec["model_path"],
        )
        db.add(fl_row)

        pm_row = PrivacyMetric(
            id=uuid.uuid4(),
            round_num=r_num,
            accountant_type="RDP",
            noise_multiplier=rec["noise_multiplier"],
            clip_norm=rec["clip_norm"],
            round_epsilon=rec["round_epsilon"],
            cumulative_epsilon=rec["privacy_epsilon_spent"],
            delta=settings.privacy_delta,
            budget_limit=settings.privacy_epsilon_budget,
            budget_exceeded=rec["privacy_epsilon_spent"] >= settings.privacy_epsilon_budget,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(pm_row)

        firestore_repo.sync_fl_round(r_num, rec)
        firestore_repo.sync_privacy_metric(
            r_num,
            {
                "roundNum": r_num,
                "accountantType": "RDP",
                "noiseMultiplier": rec["noise_multiplier"],
                "clipNorm": rec["clip_norm"],
                "roundEpsilon": rec["round_epsilon"],
                "cumulativeEpsilon": rec["privacy_epsilon_spent"],
                "delta": settings.privacy_delta,
                "budgetLimit": settings.privacy_epsilon_budget,
                "timestamp": rec["timestamp"],
            },
        )
        if rec["rejected_tenants"]:
            FL_BYZANTINE_FILTERED.inc(len(rec["rejected_tenants"]))

    await db.commit()

    FL_ROUNDS_TOTAL.set(summary["total_rounds_completed"])
    FL_GLOBAL_ACCURACY.set(summary["latest_accuracy"])
    FL_PRIVACY_EPSILON.set(summary["privacy_epsilon_total"])
    FL_ACTIVE_CLIENTS.set(len(TENANT_PROFILES))

    latest = summary["new_rounds"][-1]
    return {
        "status": "COMPLETED",
        "message": (
            f"Executed {req.rounds} real Flower FL round(s) ({req.strategy.upper()}): "
            f"Accuracy={latest['accuracy']*100:.2f}%, RDP ε={latest['privacy_epsilon_spent']:.3f}"
        ),
        "latest_round": latest,
    }


@router.get("/benchmarks")
async def get_model_benchmarks(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    rows = (await db.execute(select(ModelMetric).order_by(ModelMetric.evaluated_at.desc()))).scalars().all()
    if rows:
        seen = {}
        for r in rows:
            if r.model_name not in seen:
                seen[r.model_name] = {
                    "model_name": r.model_name,
                    "scope": r.scope,
                    "accuracy": r.accuracy,
                    "precision": r.precision,
                    "recall": r.recall,
                    "f1_score": r.f1_score,
                    "fpr": r.fpr,
                    "latency_ms": r.latency_ms,
                    "confusion_matrix": r.confusion_matrix,
                    "evaluated_at": r.evaluated_at.isoformat(),
                }
        return {"models": list(seen.values())}

    if BENCHMARK_FILE.exists():
        try:
            return json.loads(BENCHMARK_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass

    return {"models": []}


@router.post("/benchmarks/run", status_code=status.HTTP_201_CREATED)
async def execute_model_benchmarks(
    db: AsyncSession = Depends(get_db),
    _admin: User = require_role("admin"),
) -> Dict[str, Any]:
    """Train & benchmark LSTM, Random Forest, and XGBoost on tenant telemetry."""
    payload = run_comparative_benchmark(lstm_epochs=5)
    for m in payload["models"]:
        mid = uuid.uuid4()
        db.add(
            ModelMetric(
                id=mid,
                model_name=m["model_name"],
                scope=m["scope"],
                accuracy=m["accuracy"],
                precision=m["precision"],
                recall=m["recall"],
                f1_score=m["f1_score"],
                fpr=m["fpr"],
                latency_ms=m["latency_ms"],
                confusion_matrix=m["confusion_matrix"],
                evaluated_at=datetime.now(timezone.utc),
            )
        )
        firestore_repo.sync_model_metric(str(mid), m)
    await db.commit()
    return payload
