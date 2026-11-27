"""
Security Response Center Router — Automated Actions, Approval Queue, & Response History.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user, parse_uuid, require_role
from ..database import ResponseHistory, ThreatAlert, User, get_db
from ..response_engine import evaluate_and_queue_response, execute_approved_response
from ..schemas import ResponseApprovalAction, SecurityResponseRecord

router = APIRouter(prefix="/api/v1/responses", tags=["Security Response Center"])


class ManualResponseTrigger(BaseModel):
    alert_id: Optional[str] = None
    action_type: str
    target_subject: Optional[str] = None
    severity: str = "high"


@router.get("/", response_model=List[SecurityResponseRecord])
async def list_security_responses(
    approval_status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[SecurityResponseRecord]:
    stmt = select(ResponseHistory).order_by(ResponseHistory.timestamp.desc()).limit(100)
    if current_user.role != "admin":
        stmt = stmt.where(ResponseHistory.tenant_id == current_user.tenant_id)
    if approval_status:
        stmt = stmt.where(ResponseHistory.approval_status == approval_status)
    rows = (await db.execute(stmt)).scalars().all()
    return [SecurityResponseRecord.model_validate(r) for r in rows]


@router.post("/trigger", response_model=SecurityResponseRecord, status_code=201)
async def trigger_security_response(
    req: ManualResponseTrigger,
    db: AsyncSession = Depends(get_db),
    current_user: User = require_role("admin", "analyst"),
) -> SecurityResponseRecord:
    alert = None
    target_tid = current_user.tenant_id
    if req.alert_id:
        aid = parse_uuid(req.alert_id, "alert_id")
        stmt = select(ThreatAlert).where(ThreatAlert.id == aid)
        if current_user.role != "admin":
            stmt = stmt.where(ThreatAlert.tenant_id == current_user.tenant_id)
        alert = (await db.execute(stmt)).scalars().first()
        if not alert:
            raise HTTPException(status_code=404, detail="Referenced threat alert not found.")
        target_tid = alert.tenant_id

    rec = await evaluate_and_queue_response(
        db=db,
        tenant_id=target_tid,
        alert=alert,
        action_type=req.action_type,
        target_subject=req.target_subject,
        severity=req.severity,
        details={"requested_by": current_user.username},
    )
    await db.commit()
    await db.refresh(rec)
    return SecurityResponseRecord.model_validate(rec)


@router.post("/{response_id}/decide", response_model=SecurityResponseRecord)
async def decide_pending_response(
    response_id: str,
    payload: ResponseApprovalAction,
    db: AsyncSession = Depends(get_db),
    admin_user: User = require_role("admin"),
) -> SecurityResponseRecord:
    """Admin approval gate required before executing high-impact response actions."""
    rid = parse_uuid(response_id, "response_id")
    rec = (await db.execute(select(ResponseHistory).where(ResponseHistory.id == rid))).scalars().first()
    if not rec:
        raise HTTPException(status_code=404, detail="Response record not found.")
    if rec.approval_status != "pending":
        raise HTTPException(status_code=400, detail=f"Response already '{rec.approval_status}'.")

    if payload.decision == "approve":
        await execute_approved_response(db, rec, admin_user.username, note=payload.note)
    else:
        rec.approval_status = "rejected"
        rec.approved_by = admin_user.username
        details = dict(rec.details or {})
        if payload.note:
            details["rejection_note"] = payload.note
        rec.details = details

    await db.commit()
    await db.refresh(rec)
    return SecurityResponseRecord.model_validate(rec)
