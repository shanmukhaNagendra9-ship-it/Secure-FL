"""
Threats Router — Real-Time ML Threat Inference, XAI Explanations, & Secured SSE Streaming.

Fixes:
- [SEC-02]: /realtime SSE requires verified token (rejects missing/invalid with 401),
  blocks cross-tenant ?tenant_id override for non-admins (403), and removes DB fallback.
- Admin alerts bug: Global admins can acknowledge/resolve any tenant's alert.
- Adds real-time ML threat scoring + Explainable AI via POST /analyze and GET /{id}/explain.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import random
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from federated_learning.ml_benchmark import inference_engine
from ..auth import (
    get_current_tenant_id,
    get_current_user,
    parse_uuid,
    require_role,
    resolve_user_from_token,
)
from ..database import AsyncSessionLocal, AuditLog, Tenant, ThreatAlert, User, get_db
from ..metrics import CROSS_TENANT_DENIED_TOTAL, THREAT_ALERTS_TOTAL
from ..repositories import compute_audit_hash, firestore_repo
from ..response_engine import evaluate_and_queue_response
from ..schemas import (
    PaginatedResponse,
    TelemetryAnalyzeRequest,
    ThreatAlertResponse,
    ThreatAlertSummary,
)

router = APIRouter(prefix="/api/v1/threats", tags=["Threats & ML Inference"])

_SIMULATED_THREAT_PROFILES = [
    (
        "Brute Force Authentication",
        {
            "num_failed_logins": 26,
            "request_frequency": 195.0,
            "response_code_status": 1,
            "is_new_device": 1,
            "duration_ms": 42.0,
        },
        "Rapid failed authentication sequence exceeding threshold.",
    ),
    (
        "Data Exfiltration Attempt",
        {
            "bytes_transferred_kb": 185000.0,
            "session_duration_sec": 9200.0,
            "unusual_access_time": 1,
            "hour_of_day": 2,
            "is_vpn": 1,
            "request_frequency": 88.0,
        },
        "Abnormal high-volume outbound transfer during off-hours.",
    ),
    (
        "Privilege Escalation",
        {
            "privilege_level": 3,
            "secret_detection_count": 4,
            "vulnerable_deps_count": 5,
            "build_failure_count": 4,
            "file_change_count": 140,
            "repo_commit_rate": 14.0,
        },
        "Unauthorized IAM escalation & pipeline tampering detected.",
    ),
    (
        "Cross-Tenant Access Attempt",
        {
            "cross_tenant_access_attempts": 7,
            "response_code_status": 1,
            "suspicious_artifact_activity": 1,
            "is_new_device": 1,
            "unusual_access_time": 1,
            "hour_of_day": 1,
        },
        "Cross-tenant isolation boundary probe intercepted and blocked.",
    ),
]


def _confidence_to_severity(confidence: float) -> str:
    if confidence >= 0.88:
        return "critical"
    if confidence >= 0.70:
        return "high"
    if confidence >= 0.40:
        return "medium"
    return "low"


def _random_ip() -> str:
    return str(ipaddress.IPv4Address(random.randint(0x0A000001, 0x0AFEFEFE)))


@router.get("/summary", response_model=ThreatAlertSummary)
async def get_threat_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant_id),
) -> ThreatAlertSummary:
    if current_user.role == "admin":
        total = (await db.execute(select(func.count()).select_from(ThreatAlert))).scalar_one()
        type_rows = await db.execute(select(ThreatAlert.threat_type, func.count()).group_by(ThreatAlert.threat_type))
        conf_rows = await db.execute(select(ThreatAlert.confidence))
    else:
        tid = parse_uuid(tenant_id, "tenant_id")
        total = (await db.execute(select(func.count()).select_from(ThreatAlert).where(ThreatAlert.tenant_id == tid))).scalar_one()
        type_rows = await db.execute(
            select(ThreatAlert.threat_type, func.count()).where(ThreatAlert.tenant_id == tid).group_by(ThreatAlert.threat_type)
        )
        conf_rows = await db.execute(select(ThreatAlert.confidence).where(ThreatAlert.tenant_id == tid))

    by_type = {row[0]: row[1] for row in type_rows.all()}
    by_severity: Dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for (conf,) in conf_rows.all():
        sev = _confidence_to_severity(conf)
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return ThreatAlertSummary(total=total, by_severity=by_severity, by_type=by_type)


@router.get("/realtime")
async def threat_realtime_stream(
    request: Request,
    token: Optional[str] = Query(None),
    tenant_id_query: Optional[str] = Query(None, alias="tenant_id"),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """
    Strictly authenticated SSE stream.
    Rejects missing/invalid tokens with HTTP 401 and cross-tenant overrides with HTTP 403.
    """
    raw_token = token
    if not raw_token:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            raw_token = auth_hdr[7:].strip()

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required for real-time threat stream.",
        )

    current_user = await resolve_user_from_token(raw_token, db)
    is_admin = current_user.role == "admin"
    effective_tenant_id: Optional[uuid.UUID] = current_user.tenant_id

    if tenant_id_query and tenant_id_query != "all":
        requested_tid = parse_uuid(tenant_id_query, "tenant_id")
        if not is_admin and requested_tid != current_user.tenant_id:
            CROSS_TENANT_DENIED_TOTAL.labels(source="sse_realtime").inc()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-tenant SSE subscription is prohibited.",
            )
        effective_tenant_id = requested_tid
        is_admin = False

    async def _event_generator():
        last_seen_id: Optional[uuid.UUID] = None
        while True:
            if await request.is_disconnected():
                break
            async with AsyncSessionLocal() as session:
                if is_admin:
                    stmt = (
                        select(ThreatAlert)
                        .options(selectinload(ThreatAlert.tenant))
                        .order_by(ThreatAlert.timestamp.desc())
                        .limit(15)
                    )
                else:
                    stmt = (
                        select(ThreatAlert)
                        .options(selectinload(ThreatAlert.tenant))
                        .where(ThreatAlert.tenant_id == effective_tenant_id)
                        .order_by(ThreatAlert.timestamp.desc())
                        .limit(15)
                    )
                alerts = (await session.execute(stmt)).scalars().all()

            new_alerts = []
            if last_seen_id is None and alerts:
                last_seen_id = alerts[0].id
            elif alerts:
                for alert in alerts:
                    if alert.id == last_seen_id:
                        break
                    new_alerts.append(alert)
                if new_alerts:
                    last_seen_id = new_alerts[0].id

            for alert in reversed(new_alerts):
                payload = ThreatAlertResponse.model_validate(alert).model_dump(mode="json")
                if alert.tenant:
                    payload["tenant_name"] = alert.tenant.name
                yield f"data: {json.dumps(payload)}\n\n"

            yield ": heartbeat\n\n"
            await asyncio.sleep(4)

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/", response_model=PaginatedResponse[ThreatAlertResponse])
async def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    threat_type: Optional[str] = Query(None),
    tenant_filter: Optional[str] = Query(None, alias="tenant_id"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedResponse[ThreatAlertResponse]:
    base_q = select(ThreatAlert).options(selectinload(ThreatAlert.tenant))

    if current_user.role == "admin":
        if tenant_filter and tenant_filter != "all":
            base_q = base_q.where(ThreatAlert.tenant_id == parse_uuid(tenant_filter, "tenant_id"))
    else:
        if tenant_filter and tenant_filter not in ("all", str(current_user.tenant_id)):
            CROSS_TENANT_DENIED_TOTAL.labels(source="threats_list").inc()
            raise HTTPException(status_code=403, detail="Cannot query another tenant's threat alerts.")
        base_q = base_q.where(ThreatAlert.tenant_id == current_user.tenant_id)

    if status_filter:
        if status_filter not in ("open", "acknowledged", "resolved"):
            raise HTTPException(400, detail="status must be open | acknowledged | resolved")
        base_q = base_q.where(ThreatAlert.status == status_filter)

    if threat_type:
        base_q = base_q.where(ThreatAlert.threat_type.ilike(f"%{threat_type}%"))

    total: int = (await db.execute(select(func.count()).select_from(base_q.subquery()))).scalar_one()
    offset = (page - 1) * page_size
    alerts = (
        await db.execute(base_q.order_by(ThreatAlert.timestamp.desc()).offset(offset).limit(page_size))
    ).scalars().all()

    items = []
    for r in alerts:
        item = ThreatAlertResponse.model_validate(r)
        if r.tenant:
            item.tenant_name = r.tenant.name
        items.append(item)

    return PaginatedResponse[ThreatAlertResponse](items=items, total=total, page=page, page_size=page_size)


@router.post("/analyze", response_model=Dict[str, Any])
async def analyze_telemetry_event(
    req: TelemetryAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Run real ML threat inference (LSTM / Random Forest / XGBoost + Autoencoder),
    generate SHAP/gradient XAI attributions, persist threat_events, and escalate alerts.
    """
    target_tid = current_user.tenant_id
    if req.tenant_id:
        parsed_tid = parse_uuid(req.tenant_id, "tenant_id")
        if current_user.role != "admin" and parsed_tid != current_user.tenant_id:
            CROSS_TENANT_DENIED_TOTAL.labels(source="threats_analyze").inc()
            raise HTTPException(status_code=403, detail="Cannot submit telemetry for another tenant.")
        target_tid = parsed_tid

    tenant_obj = (await db.execute(select(Tenant).where(Tenant.id == target_tid))).scalars().first()
    tenant_name = tenant_obj.name if tenant_obj else str(target_tid)

    analysis = inference_engine.analyze(req.features, model_type=req.model_type)
    now = datetime.now(timezone.utc)
    event_id = str(uuid.uuid4())

    firestore_repo.sync_threat_event(
        str(target_tid),
        event_id,
        {
            "id": event_id,
            "tenantId": str(target_tid),
            "threatLabel": analysis["threat_label"],
            "threatType": analysis["threat_type"],
            "severity": analysis["severity"],
            "anomalyScore": analysis["anomaly_score"],
            "confidence": analysis["confidence"],
            "mlModel": analysis["model_used"],
            "shapExplanation": analysis,
            "recommendedAction": analysis["recommended_action"],
            "sourceIp": req.source_ip,
            "timestamp": now.isoformat(),
        },
    )

    alert_id: Optional[str] = None
    response_id: Optional[str] = None

    if analysis["is_threat"]:
        alert = ThreatAlert(
            id=uuid.uuid4(),
            tenant_id=target_tid,
            threat_type=analysis["threat_type"],
            confidence=analysis["confidence"],
            anomaly_score=analysis["anomaly_score"],
            severity=analysis["severity"],
            timestamp=now,
            source_ip=req.source_ip,
            destination_ip=req.destination_ip,
            description=analysis["explanation"],
            ml_model=analysis["model_used"],
            xai_explanation=analysis,
            recommended_action=analysis["recommended_action"],
            status="open",
        )
        db.add(alert)
        await db.flush()
        alert_id = str(alert.id)

        THREAT_ALERTS_TOTAL.labels(
            tenant_id=str(target_tid),
            severity=analysis["severity"],
            threat_type=alert.threat_type,
        ).inc()

        firestore_repo.sync_security_alert(
            str(target_tid),
            alert_id,
            {
                "id": alert_id,
                "tenantId": str(target_tid),
                "threatEventId": event_id,
                "threatType": alert.threat_type,
                "severity": analysis["severity"],
                "confidence": analysis["confidence"],
                "status": "open",
                "requiresApproval": analysis["severity"] == "critical",
                "timestamp": now.isoformat(),
            },
        )

        resp_rec = await evaluate_and_queue_response(
            db=db,
            tenant_id=target_tid,
            alert=alert,
            action_type=analysis["recommended_action"],
            target_subject=req.source_ip,
            severity=analysis["severity"],
            details={"ml_model": analysis["model_used"], "confidence": analysis["confidence"]},
        )
        response_id = str(resp_rec.id)
        await db.commit()

    return {
        "event_id": event_id,
        "tenant_id": str(target_tid),
        "tenant_name": tenant_name,
        "alert_id": alert_id,
        "response_id": response_id,
        **analysis,
    }


@router.get("/{alert_id}/explain", response_model=Dict[str, Any])
async def explain_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    aid = parse_uuid(alert_id, "alert_id")
    stmt = select(ThreatAlert).options(selectinload(ThreatAlert.tenant)).where(ThreatAlert.id == aid)
    if current_user.role != "admin":
        stmt = stmt.where(ThreatAlert.tenant_id == current_user.tenant_id)
    alert = (await db.execute(stmt)).scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Threat alert not found.")

    if alert.xai_explanation:
        return {
            "alert_id": str(alert.id),
            "tenant_name": alert.tenant.name if alert.tenant else str(alert.tenant_id),
            "threat_type": alert.threat_type,
            **alert.xai_explanation,
        }

    # Synthesize deterministic XAI view from alert type when pre-existing alert predates XAI persistence
    matching = next(
        (feats for name, feats, _d in _SIMULATED_THREAT_PROFILES if name.split()[0].lower() in alert.threat_type.lower()),
        {"request_frequency": 95.0, "cross_tenant_access_attempts": 3},
    )
    xai = inference_engine.analyze(matching, model_type="lstm")
    return {
        "alert_id": str(alert.id),
        "tenant_name": alert.tenant.name if alert.tenant else str(alert.tenant_id),
        "threat_type": alert.threat_type,
        **xai,
    }


@router.post("/{alert_id}/acknowledge", response_model=ThreatAlertResponse)
async def acknowledge_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatAlertResponse:
    aid = parse_uuid(alert_id, "alert_id")
    stmt = select(ThreatAlert).options(selectinload(ThreatAlert.tenant)).where(ThreatAlert.id == aid)
    if current_user.role != "admin":
        stmt = stmt.where(ThreatAlert.tenant_id == current_user.tenant_id)
    alert = (await db.execute(stmt)).scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Threat alert not found.")
    if alert.status != "open":
        raise HTTPException(status_code=400, detail=f"Alert is already {alert.status}.")

    alert.status = "acknowledged"
    alert.acknowledged_by = current_user.username
    alert.acknowledged_at = datetime.now(timezone.utc)

    details = {"alert_id": str(alert.id), "threat_type": alert.threat_type, "by": current_user.username}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=alert.tenant_id,
            event_type="threat_acknowledged",
            severity="medium",
            timestamp=datetime.now(timezone.utc),
            actor_uid=current_user.username,
            details=details,
            source_ip=alert.source_ip,
            integrity_hash=compute_audit_hash(str(alert.tenant_id), "threat_acknowledged", "medium", details),
        )
    )
    await db.commit()
    await db.refresh(alert)
    firestore_repo.sync_security_alert(
        str(alert.tenant_id),
        str(alert.id),
        {"status": "acknowledged", "acknowledgedBy": current_user.username},
    )
    resp = ThreatAlertResponse.model_validate(alert)
    if alert.tenant:
        resp.tenant_name = alert.tenant.name
    return resp


@router.post("/{alert_id}/resolve", response_model=ThreatAlertResponse)
async def resolve_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatAlertResponse:
    aid = parse_uuid(alert_id, "alert_id")
    stmt = select(ThreatAlert).options(selectinload(ThreatAlert.tenant)).where(ThreatAlert.id == aid)
    if current_user.role != "admin":
        stmt = stmt.where(ThreatAlert.tenant_id == current_user.tenant_id)
    alert = (await db.execute(stmt)).scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Threat alert not found.")
    if alert.status == "resolved":
        raise HTTPException(status_code=400, detail="Alert is already resolved.")

    alert.status = "resolved"
    if not alert.acknowledged_by:
        alert.acknowledged_by = current_user.username
        alert.acknowledged_at = datetime.now(timezone.utc)

    details = {"alert_id": str(alert.id), "threat_type": alert.threat_type, "by": current_user.username}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=alert.tenant_id,
            event_type="threat_resolved",
            severity="low",
            timestamp=datetime.now(timezone.utc),
            actor_uid=current_user.username,
            details=details,
            integrity_hash=compute_audit_hash(str(alert.tenant_id), "threat_resolved", "low", details),
        )
    )
    await db.commit()
    await db.refresh(alert)
    firestore_repo.sync_security_alert(str(alert.tenant_id), str(alert.id), {"status": "resolved"})
    resp = ThreatAlertResponse.model_validate(alert)
    if alert.tenant:
        resp.tenant_name = alert.tenant.name
    return resp


@router.post("/simulate", response_model=ThreatAlertResponse, status_code=201)
async def simulate_threat(
    target_tenant_id: Optional[str] = Query(None, alias="tenant_id"),
    db: AsyncSession = Depends(get_db),
    current_user: User = require_role("admin", "analyst"),
) -> ThreatAlertResponse:
    """
    Inject a synthetic security telemetry event and evaluate it through the real ML + XAI pipeline.
    Clearly tagged as synthetic telemetry in the description & metadata.
    """
    chosen_tenant_id = current_user.tenant_id
    if current_user.role == "admin":
        if target_tenant_id and target_tenant_id != "random":
            chosen_tenant_id = parse_uuid(target_tenant_id, "tenant_id")
        else:
            t_ids = (await db.execute(select(Tenant.id).where(Tenant.is_active.is_(True)))).scalars().all()
            if t_ids:
                chosen_tenant_id = random.choice(t_ids)

    target_t = (await db.execute(select(Tenant).where(Tenant.id == chosen_tenant_id))).scalars().first()
    t_name = target_t.name if target_t else "Tenant"

    label, feats, summary = random.choice(_SIMULATED_THREAT_PROFILES)
    xai = inference_engine.analyze(feats, model_type="lstm")
    src_ip = _random_ip()
    dst_ip = _random_ip()
    now = datetime.now(timezone.utc)

    alert = ThreatAlert(
        id=uuid.uuid4(),
        tenant_id=chosen_tenant_id,
        threat_type=label,
        confidence=xai["confidence"],
        anomaly_score=xai["anomaly_score"],
        severity=xai["severity"],
        timestamp=now,
        source_ip=src_ip,
        destination_ip=dst_ip,
        description=f"[Synthetic Telemetry] {summary} {xai['explanation']}",
        ml_model="lstm",
        xai_explanation=xai,
        recommended_action=xai["recommended_action"],
        status="open",
    )
    db.add(alert)
    await db.flush()

    details = {"threat_type": label, "confidence": xai["confidence"], "synthetic": True, "simulated_by": current_user.username}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=chosen_tenant_id,
            event_type="threat_simulated",
            severity=xai["severity"] if xai["severity"] in ("low", "medium", "high", "critical") else "high",
            timestamp=now,
            actor_uid=current_user.username,
            details=details,
            source_ip=src_ip,
            integrity_hash=compute_audit_hash(str(chosen_tenant_id), "threat_simulated", "high", details),
        )
    )
    await evaluate_and_queue_response(
        db=db,
        tenant_id=chosen_tenant_id,
        alert=alert,
        action_type=xai["recommended_action"],
        target_subject=src_ip,
        severity=xai["severity"],
        details={"synthetic": True, "confidence": xai["confidence"]},
    )
    await db.commit()
    await db.refresh(alert)

    resp = ThreatAlertResponse.model_validate(alert)
    resp.tenant_name = t_name
    return resp
