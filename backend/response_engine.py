"""
Automated Security Response Engine & Admin Approval Gate.

Handles:
- Brute-force authentication tracking & temporary restriction escalation
- Cross-tenant access probe detection
- Threat severity evaluation -> security_alerts + response_history
- Mandatory admin approval gate for high-impact actions (revoke_session, restrict_account, block_ip)
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .database import AuditLog, ResponseHistory, ThreatAlert, User
from .firebase_client import firebase_service
from .metrics import SECURITY_RESPONSES_TOTAL, THREAT_ALERTS_TOTAL
from .repositories import compute_audit_hash, firestore_repo

logger = logging.getLogger("SecureFL.ResponseEngine")

HIGH_IMPACT_ACTIONS = {"restrict_account", "revoke_session", "block_ip"}


async def evaluate_and_queue_response(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    alert: Optional[ThreatAlert],
    action_type: str,
    target_subject: Optional[str],
    severity: str,
    details: Optional[Dict[str, Any]] = None,
    auto_execute_low_impact: bool = True,
) -> ResponseHistory:
    """
    Create a response_history entry. High-impact actions always start in 'pending'
    until an administrator explicitly approves them.
    """
    requires_approval = action_type in HIGH_IMPACT_ACTIONS
    approval_status = "pending" if requires_approval else ("executed" if auto_execute_low_impact else "pending")

    rec = ResponseHistory(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        alert_id=alert.id if alert else None,
        action_type=action_type,
        target_subject=target_subject,
        approval_status=approval_status,
        requires_approval=requires_approval,
        approved_by="system_policy" if approval_status == "executed" else None,
        approved_at=datetime.now(timezone.utc) if approval_status == "executed" else None,
        details=details or {},
        timestamp=datetime.now(timezone.utc),
    )
    db.add(rec)

    SECURITY_RESPONSES_TOTAL.labels(action_type=action_type, status=approval_status).inc()
    if alert is not None:
        THREAT_ALERTS_TOTAL.labels(
            tenant_id=str(tenant_id),
            severity=severity,
            threat_type=alert.threat_type,
        ).inc()

    audit = AuditLog(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        event_type="security_response_queued" if requires_approval else "security_response_executed",
        severity=severity if severity in ("low", "medium", "high", "critical") else "medium",
        timestamp=datetime.now(timezone.utc),
        details={
            "response_id": str(rec.id),
            "action_type": action_type,
            "target_subject": target_subject,
            "approval_status": approval_status,
            **(details or {}),
        },
        integrity_hash=compute_audit_hash(
            str(tenant_id),
            "security_response",
            severity,
            {"action_type": action_type, "target": target_subject},
        ),
    )
    db.add(audit)

    firestore_repo.sync_response_history(
        str(tenant_id),
        str(rec.id),
        {
            "id": str(rec.id),
            "tenantId": str(tenant_id),
            "alertId": str(alert.id) if alert else None,
            "actionType": action_type,
            "targetSubject": target_subject,
            "approvalStatus": approval_status,
            "requiresApproval": requires_approval,
            "details": details or {},
            "timestamp": rec.timestamp.isoformat(),
        },
    )
    return rec


async def execute_approved_response(
    db: AsyncSession,
    response_rec: ResponseHistory,
    admin_username: str,
    note: Optional[str] = None,
) -> ResponseHistory:
    """Execute a pending security response after explicit administrator approval."""
    now = datetime.now(timezone.utc)
    response_rec.approval_status = "executed"
    response_rec.approved_by = admin_username
    response_rec.approved_at = now
    details = dict(response_rec.details or {})
    if note:
        details["approval_note"] = note

    if response_rec.action_type in ("restrict_account", "revoke_session") and response_rec.target_subject:
        res = await db.execute(
            select(User).where(
                (User.username == response_rec.target_subject)
                | (User.email == response_rec.target_subject)
            )
        )
        target_user = res.scalars().first()
        if target_user:
            if response_rec.action_type == "restrict_account":
                target_user.is_restricted = True
                details["account_restricted"] = target_user.username
            if target_user.firebase_uid:
                firebase_service.revoke_refresh_tokens(target_user.firebase_uid)
                details["firebase_sessions_revoked"] = True

    response_rec.details = details
    SECURITY_RESPONSES_TOTAL.labels(action_type=response_rec.action_type, status="executed").inc()

    audit = AuditLog(
        id=uuid.uuid4(),
        tenant_id=response_rec.tenant_id,
        event_type="security_response_approved_executed",
        severity="high",
        timestamp=now,
        actor_uid=admin_username,
        details={
            "response_id": str(response_rec.id),
            "action_type": response_rec.action_type,
            "approved_by": admin_username,
            **details,
        },
        integrity_hash=compute_audit_hash(
            str(response_rec.tenant_id),
            "security_response_approved_executed",
            "high",
            details,
        ),
    )
    db.add(audit)

    firestore_repo.sync_response_history(
        str(response_rec.tenant_id),
        str(response_rec.id),
        {
            "approvalStatus": "executed",
            "approvedBy": admin_username,
            "approvedAt": now.isoformat(),
            "details": details,
        },
    )
    return response_rec


async def record_failed_login_attempt(
    db: AsyncSession,
    user: Optional[User],
    username: str,
    source_ip: Optional[str],
) -> None:
    """Track brute-force login attempts and raise an alert + pending restriction at >= 5 failures."""
    if user is None:
        return
    user.failed_login_attempts = int(user.failed_login_attempts or 0) + 1
    if user.failed_login_attempts >= 5:
        alert = ThreatAlert(
            id=uuid.uuid4(),
            tenant_id=user.tenant_id,
            threat_type="Brute Force Authentication",
            confidence=0.95,
            anomaly_score=0.92,
            severity="critical",
            timestamp=datetime.now(timezone.utc),
            source_ip=source_ip,
            description=f"{user.failed_login_attempts} consecutive failed login attempts for '{username}'.",
            ml_model="Rule+TelemetryGuard",
            recommended_action="restrict_account",
            status="open",
        )
        db.add(alert)
        await db.flush()
        await evaluate_and_queue_response(
            db=db,
            tenant_id=user.tenant_id,
            alert=alert,
            action_type="restrict_account",
            target_subject=user.username,
            severity="critical",
            details={"failed_attempts": user.failed_login_attempts, "source_ip": source_ip},
        )
