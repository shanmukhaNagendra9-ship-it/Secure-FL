"""
Audit Trail, Integrity Verification, CSV & PDF Security Report Export Router.
"""
from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_tenant_id, get_current_user, parse_uuid
from ..database import AuditLog, FLRound, ThreatAlert, User, get_db
from ..metrics import CROSS_TENANT_DENIED_TOTAL
from ..repositories import compute_audit_hash, firestore_repo
from ..schemas import AuditLogResponse, PaginatedResponse
from ..storage_service import tenant_storage

router = APIRouter(prefix="/api/v1/audit", tags=["Audit & Security Reports"])


class AuditLogCreate(BaseModel):
    event_type: str = Field(..., max_length=128)
    severity: str = Field(default="low", pattern="^(low|medium|high|critical)$")
    details: Dict[str, Any] = Field(default_factory=dict)
    source_ip: Optional[str] = None


@router.get("/logs", response_model=PaginatedResponse[AuditLogResponse])
async def list_audit_logs(
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    tenant_filter: Optional[str] = Query(None, alias="tenant_id"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedResponse[AuditLogResponse]:
    if current_user.role == "admin":
        if tenant_filter and tenant_filter != "all":
            tid = parse_uuid(tenant_filter, "tenant_id")
            query = select(AuditLog).where(AuditLog.tenant_id == tid)
            count_query = select(func.count(AuditLog.id)).where(AuditLog.tenant_id == tid)
        else:
            query = select(AuditLog)
            count_query = select(func.count(AuditLog.id))
    else:
        if tenant_filter and tenant_filter not in ("all", str(current_user.tenant_id)):
            CROSS_TENANT_DENIED_TOTAL.labels(source="audit_list").inc()
            raise HTTPException(status_code=403, detail="Cross-tenant audit access prohibited.")
        query = select(AuditLog).where(AuditLog.tenant_id == current_user.tenant_id)
        count_query = select(func.count(AuditLog.id)).where(AuditLog.tenant_id == current_user.tenant_id)

    if event_type:
        query = query.where(AuditLog.event_type == event_type)
        count_query = count_query.where(AuditLog.event_type == event_type)
    if severity:
        query = query.where(AuditLog.severity == severity)
        count_query = count_query.where(AuditLog.severity == severity)

    total = (await db.execute(count_query)).scalar_one() or 0
    offset = (page - 1) * page_size
    logs = (
        await db.execute(query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(page_size))
    ).scalars().all()

    return PaginatedResponse(
        items=[AuditLogResponse.model_validate(log) for log in logs],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/summary")
async def get_audit_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if current_user.role == "admin":
        rows = (await db.execute(select(AuditLog.severity, func.count(AuditLog.id)).group_by(AuditLog.severity))).all()
    else:
        rows = (
            await db.execute(
                select(AuditLog.severity, func.count(AuditLog.id))
                .where(AuditLog.tenant_id == current_user.tenant_id)
                .group_by(AuditLog.severity)
            )
        ).all()

    by_severity = {sev: count for sev, count in rows}
    return {
        "tenant_id": "all" if current_user.role == "admin" else str(current_user.tenant_id),
        "total_audit_events": sum(by_severity.values()),
        "by_severity": {
            "low": by_severity.get("low", 0),
            "medium": by_severity.get("medium", 0),
            "high": by_severity.get("high", 0),
            "critical": by_severity.get("critical", 0),
        },
    }


@router.get("/logs/export")
async def export_audit_logs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    if current_user.role == "admin":
        stmt = select(AuditLog).order_by(AuditLog.timestamp.desc())
        scope_label = "global_admin"
    else:
        stmt = select(AuditLog).where(AuditLog.tenant_id == current_user.tenant_id).order_by(AuditLog.timestamp.desc())
        scope_label = str(current_user.tenant_id)

    logs = (await db.execute(stmt)).scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Tenant ID", "Timestamp", "Event Type", "Severity", "Source IP", "Integrity Hash", "Details"])
    for log in logs:
        writer.writerow([
            str(log.id),
            str(log.tenant_id),
            log.timestamp.isoformat(),
            log.event_type,
            log.severity,
            log.source_ip or "N/A",
            log.integrity_hash or "",
            str(log.details or {}),
        ])

    csv_bytes = output.getvalue().encode("utf-8")
    filename = f"audit_logs_{scope_label}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    tenant_storage.save_report(str(current_user.tenant_id), filename, csv_bytes, "text/csv")

    return StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/pdf")
async def export_security_report_pdf(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Generate a PDF Cybersecurity & Compliance Report and archive it to Firebase Storage / local fallback."""
    is_admin = current_user.role == "admin"
    if is_admin:
        alerts = (await db.execute(select(ThreatAlert).order_by(ThreatAlert.timestamp.desc()).limit(15))).scalars().all()
        audits = (await db.execute(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(15))).scalars().all()
    else:
        alerts = (
            await db.execute(
                select(ThreatAlert)
                .where(ThreatAlert.tenant_id == current_user.tenant_id)
                .order_by(ThreatAlert.timestamp.desc())
                .limit(15)
            )
        ).scalars().all()
        audits = (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.tenant_id == current_user.tenant_id)
                .order_by(AuditLog.timestamp.desc())
                .limit(15)
            )
        ).scalars().all()

    fl_round = (await db.execute(select(FLRound).order_by(FLRound.round_num.desc()).limit(1))).scalars().first()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("SecureFL Multi-Tenant Cloud Security Report", styles["Title"]),
        Spacer(1, 8),
        Paragraph(
            (
                f"Generated: {datetime.now(timezone.utc).isoformat()} | "
                f"Scope: {'All Tenants (Admin)' if is_admin else str(current_user.tenant_id)} | "
                f"Generated By: {current_user.username}"
            ),
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph("1. Cryptographic Isolation & Federated Learning Posture", styles["Heading2"]),
        Paragraph(
            f"Encryption: AES-256-GCM (HKDF-SHA256) | Latest FL Round: {fl_round.round_num if fl_round else 0} | "
            f"Accuracy: {f'{fl_round.accuracy*100:.2f}%' if fl_round else 'N/A'} | "
            f"Cumulative DP Epsilon: {f'{fl_round.privacy_epsilon:.3f}' if fl_round else 'N/A'}",
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph("2. Recent Threat Detections", styles["Heading2"]),
    ]

    threat_rows = [["Threat Type", "Severity", "Confidence", "Status", "Source IP"]]
    for a in alerts:
        threat_rows.append([
            a.threat_type[:28],
            (a.severity or "high").upper(),
            f"{a.confidence*100:.1f}%",
            a.status,
            a.source_ip or "internal",
        ])
    t_table = Table(threat_rows, hAlign="LEFT")
    t_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ])
    )
    story.append(t_table)
    story.append(Spacer(1, 14))
    story.append(Paragraph("3. Recent Immutable Audit Events", styles["Heading2"]))

    audit_rows = [["Event Type", "Severity", "Actor", "SHA-256 Prefix"]]
    for entry in audits:
        audit_rows.append([
            entry.event_type[:32],
            entry.severity.upper(),
            entry.actor_uid or "system",
            (entry.integrity_hash or "")[:16],
        ])
    a_table = Table(audit_rows, hAlign="LEFT")
    a_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#312e81")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ])
    )
    story.append(a_table)

    doc.build(story)
    pdf_bytes = buf.getvalue()
    filename = f"security_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    tenant_storage.save_report(str(current_user.tenant_id), filename, pdf_bytes, "application/pdf")

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.post("/logs", response_model=AuditLogResponse, status_code=status.HTTP_201_CREATED)
async def create_audit_log(
    payload: AuditLogCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant_id),
) -> AuditLogResponse:
    tenant_uuid = parse_uuid(tenant_id, "tenant_id")
    ihash = compute_audit_hash(tenant_id, payload.event_type, payload.severity, payload.details)
    new_log = AuditLog(
        id=uuid.uuid4(),
        tenant_id=tenant_uuid,
        event_type=payload.event_type,
        severity=payload.severity,
        timestamp=datetime.now(timezone.utc),
        actor_uid=current_user.username,
        details=payload.details,
        source_ip=payload.source_ip,
        integrity_hash=ihash,
    )
    db.add(new_log)
    await db.commit()
    await db.refresh(new_log)

    firestore_repo.sync_audit_log(
        tenant_id,
        str(new_log.id),
        {
            "id": str(new_log.id),
            "tenantId": tenant_id,
            "actorUid": current_user.username,
            "eventType": new_log.event_type,
            "severity": new_log.severity,
            "sourceIp": new_log.source_ip,
            "details": new_log.details,
            "integrityHash": ihash,
            "timestamp": new_log.timestamp.isoformat(),
        },
    )
    return AuditLogResponse.model_validate(new_log)
