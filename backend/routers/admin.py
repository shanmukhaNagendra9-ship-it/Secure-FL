"""
Admin Verification, Governance, and Firebase Claims Sync Router.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .federated import _read_live_metrics
from ..auth import hash_password, parse_uuid, require_role
from ..database import AuditLog, Tenant, ThreatAlert, User, get_db
from ..firebase_client import firebase_service
from ..repositories import compute_audit_hash, firestore_repo
from ..schemas import UserResponse, UserStatusUpdate, UserVerifyAction

router = APIRouter(prefix="/api/v1/admin", tags=["Admin Verification & Governance"])


class AdminCreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8)
    email: Optional[str] = None
    full_name: Optional[str] = None
    tenant_id: str
    role: str = Field(default="user", pattern="^(admin|analyst|user)$")
    is_verified: bool = True


class UpdateUserRoleRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|analyst|user)$")


class ChangeTenantRequest(BaseModel):
    tenant_id: str


def _serialize_user(u: User) -> UserResponse:
    t_name = u.tenant.name if u.tenant else "System / Unassigned"
    return UserResponse(
        id=u.id,
        firebase_uid=u.firebase_uid,
        username=u.username,
        email=u.email,
        full_name=u.full_name,
        tenant_id=u.tenant_id,
        tenant_name=t_name,
        role=u.role,
        is_active=u.is_active,
        is_verified=u.is_verified,
        is_restricted=u.is_restricted,
        created_at=u.created_at,
        verified_by=u.verified_by,
        verified_at=u.verified_at,
    )


def _sync_user_to_firebase(u: User) -> None:
    uid = u.firebase_uid or str(u.id)
    if u.firebase_uid:
        firebase_service.set_custom_claims(
            u.firebase_uid,
            {
                "role": u.role,
                "tenant_id": str(u.tenant_id),
                "is_verified": bool(u.is_verified),
                "is_active": bool(u.is_active and not u.is_restricted),
            },
        )
    firestore_repo.sync_user(
        uid,
        {
            "uid": uid,
            "username": u.username,
            "email": u.email,
            "displayName": u.full_name or u.username,
            "role": u.role,
            "tenantId": str(u.tenant_id),
            "isVerified": bool(u.is_verified),
            "isActive": bool(u.is_active),
            "isRestricted": bool(u.is_restricted),
            "verifiedBy": u.verified_by,
            "updatedAt": datetime.now(timezone.utc).isoformat(),
        },
    )


@router.get("/users", response_model=List[UserResponse])
async def list_all_users(
    pending_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    _admin: User = require_role("admin"),
) -> List[UserResponse]:
    stmt = select(User).options(selectinload(User.tenant)).order_by(User.created_at.desc())
    if pending_only:
        stmt = stmt.where(User.is_verified.is_(False))
    res = await db.execute(stmt)
    return [_serialize_user(u) for u in res.scalars().all()]


@router.get("/pending-users", response_model=List[UserResponse])
async def list_pending_users(
    db: AsyncSession = Depends(get_db),
    _admin: User = require_role("admin"),
) -> List[UserResponse]:
    stmt = (
        select(User)
        .options(selectinload(User.tenant))
        .where(User.is_verified.is_(False))
        .order_by(User.created_at.desc())
    )
    res = await db.execute(stmt)
    return [_serialize_user(u) for u in res.scalars().all()]


@router.post("/users/{user_id}/verify", response_model=Dict[str, Any])
async def verify_user(
    user_id: str,
    payload: UserVerifyAction,
    db: AsyncSession = Depends(get_db),
    admin_user: User = require_role("admin"),
) -> Dict[str, Any]:
    uid = parse_uuid(user_id, "user_id")
    res = await db.execute(select(User).options(selectinload(User.tenant)).where(User.id == uid))
    user = res.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.action == "approve":
        if payload.tenant_id:
            tid = parse_uuid(payload.tenant_id, "tenant_id")
            t_obj = (await db.execute(select(Tenant).where(Tenant.id == tid))).scalars().first()
            if not t_obj:
                raise HTTPException(status_code=404, detail="Target tenant not found")
            user.tenant_id = tid
        if payload.role:
            user.role = payload.role

        user.is_verified = True
        user.verified_by = admin_user.username
        user.verified_at = datetime.now(timezone.utc)

        details = {
            "verified_username": user.username,
            "approved_by": admin_user.username,
            "role": user.role,
        }
        db.add(
            AuditLog(
                id=uuid.uuid4(),
                tenant_id=user.tenant_id,
                event_type="user_verified",
                severity="medium",
                timestamp=datetime.now(timezone.utc),
                actor_uid=admin_user.username,
                details=details,
                integrity_hash=compute_audit_hash(str(user.tenant_id), "user_verified", "medium", details),
            )
        )
        await db.commit()
        await db.refresh(user)
        _sync_user_to_firebase(user)
        return {
            "status": "APPROVED",
            "message": f"User {user.username} successfully verified and activated.",
            "user": _serialize_user(user).model_dump(mode="json"),
        }

    username = user.username
    tenant_id = user.tenant_id
    if user.firebase_uid:
        firebase_service.revoke_refresh_tokens(user.firebase_uid)
    await db.delete(user)
    details = {"rejected_username": username, "rejected_by": admin_user.username}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            event_type="user_rejected",
            severity="high",
            timestamp=datetime.now(timezone.utc),
            actor_uid=admin_user.username,
            details=details,
            integrity_hash=compute_audit_hash(str(tenant_id), "user_rejected", "high", details),
        )
    )
    await db.commit()
    return {
        "status": "REJECTED",
        "message": f"Registration request for {username} has been rejected.",
    }


@router.post("/users/{user_id}/toggle-active", response_model=UserResponse)
async def toggle_user_active(
    user_id: str,
    payload: UserStatusUpdate,
    db: AsyncSession = Depends(get_db),
    admin_user: User = require_role("admin"),
) -> UserResponse:
    uid = parse_uuid(user_id, "user_id")
    user = (await db.execute(select(User).options(selectinload(User.tenant)).where(User.id == uid))).scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = payload.is_active
    if not payload.is_active and user.firebase_uid:
        firebase_service.revoke_refresh_tokens(user.firebase_uid)

    details = {"target_username": user.username, "is_active": user.is_active, "changed_by": admin_user.username}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=user.tenant_id,
            event_type="user_status_changed",
            severity="medium",
            timestamp=datetime.now(timezone.utc),
            actor_uid=admin_user.username,
            details=details,
            integrity_hash=compute_audit_hash(str(user.tenant_id), "user_status_changed", "medium", details),
        )
    )
    await db.commit()
    await db.refresh(user)
    _sync_user_to_firebase(user)
    return _serialize_user(user)


@router.post("/users/{user_id}/unrestrict", response_model=UserResponse)
async def unrestrict_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin_user: User = require_role("admin"),
) -> UserResponse:
    uid = parse_uuid(user_id, "user_id")
    user = (await db.execute(select(User).options(selectinload(User.tenant)).where(User.id == uid))).scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_restricted = False
    user.failed_login_attempts = 0
    details = {"target_username": user.username, "unrestricted_by": admin_user.username}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=user.tenant_id,
            event_type="user_restriction_lifted",
            severity="medium",
            timestamp=datetime.now(timezone.utc),
            actor_uid=admin_user.username,
            details=details,
            integrity_hash=compute_audit_hash(str(user.tenant_id), "user_restriction_lifted", "medium", details),
        )
    )
    await db.commit()
    await db.refresh(user)
    _sync_user_to_firebase(user)
    return _serialize_user(user)


@router.post("/users/{user_id}/revoke-sessions", response_model=Dict[str, Any])
async def revoke_user_sessions(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin_user: User = require_role("admin"),
) -> Dict[str, Any]:
    uid = parse_uuid(user_id, "user_id")
    user = (await db.execute(select(User).where(User.id == uid))).scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    revoked_fb = False
    if user.firebase_uid:
        revoked_fb = firebase_service.revoke_refresh_tokens(user.firebase_uid)

    details = {"target_username": user.username, "revoked_by": admin_user.username, "firebase_revoked": revoked_fb}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=user.tenant_id,
            event_type="user_sessions_revoked",
            severity="high",
            timestamp=datetime.now(timezone.utc),
            actor_uid=admin_user.username,
            details=details,
            integrity_hash=compute_audit_hash(str(user.tenant_id), "user_sessions_revoked", "high", details),
        )
    )
    await db.commit()
    return {"status": "REVOKED", "username": user.username, "firebase_revoked": revoked_fb}


@router.post("/users/{user_id}/update-role", response_model=UserResponse)
async def update_user_role(
    user_id: str,
    payload: UpdateUserRoleRequest,
    db: AsyncSession = Depends(get_db),
    admin_user: User = require_role("admin"),
) -> UserResponse:
    uid = parse_uuid(user_id, "user_id")
    user = (await db.execute(select(User).options(selectinload(User.tenant)).where(User.id == uid))).scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = user.role
    user.role = payload.role
    details = {"target_username": user.username, "old_role": old_role, "new_role": user.role, "changed_by": admin_user.username}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=user.tenant_id,
            event_type="user_role_updated",
            severity="high",
            timestamp=datetime.now(timezone.utc),
            actor_uid=admin_user.username,
            details=details,
            integrity_hash=compute_audit_hash(str(user.tenant_id), "user_role_updated", "high", details),
        )
    )
    await db.commit()
    await db.refresh(user)
    _sync_user_to_firebase(user)
    return _serialize_user(user)


@router.post("/users/{user_id}/change-tenant", response_model=UserResponse)
async def change_user_tenant(
    user_id: str,
    payload: ChangeTenantRequest,
    db: AsyncSession = Depends(get_db),
    admin_user: User = require_role("admin"),
) -> UserResponse:
    uid = parse_uuid(user_id, "user_id")
    new_tid = parse_uuid(payload.tenant_id, "tenant_id")

    tenant = (await db.execute(select(Tenant).where(Tenant.id == new_tid))).scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Target tenant does not exist")

    user = (await db.execute(select(User).options(selectinload(User.tenant)).where(User.id == uid))).scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.tenant_id = new_tid
    details = {"target_username": user.username, "new_tenant": tenant.name, "reassigned_by": admin_user.username}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=new_tid,
            event_type="user_tenant_reassigned",
            severity="high",
            timestamp=datetime.now(timezone.utc),
            actor_uid=admin_user.username,
            details=details,
            integrity_hash=compute_audit_hash(str(new_tid), "user_tenant_reassigned", "high", details),
        )
    )
    await db.commit()
    await db.refresh(user)
    _sync_user_to_firebase(user)
    return _serialize_user(user)


@router.post("/users/create", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def admin_create_user(
    payload: AdminCreateUserRequest,
    db: AsyncSession = Depends(get_db),
    admin_user: User = require_role("admin"),
) -> UserResponse:
    existing = (await db.execute(select(User).where(User.username == payload.username))).scalars().first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    tid = parse_uuid(payload.tenant_id, "tenant_id")
    tenant = (await db.execute(select(Tenant).where(Tenant.id == tid))).scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant does not exist")

    fb_uid = None
    if payload.email and firebase_service.is_firebase_active:
        try:
            fb_uid = firebase_service.create_auth_user(
                email=payload.email,
                password=payload.password,
                display_name=payload.full_name or payload.username,
            )
        except Exception:
            fb_uid = None

    new_user = User(
        id=uuid.uuid4(),
        firebase_uid=fb_uid,
        username=payload.username,
        hashed_password=hash_password(payload.password),
        email=payload.email,
        full_name=payload.full_name,
        tenant_id=tid,
        role=payload.role,
        is_active=True,
        is_verified=payload.is_verified,
        created_at=datetime.now(timezone.utc),
        verified_by=admin_user.username if payload.is_verified else None,
        verified_at=datetime.now(timezone.utc) if payload.is_verified else None,
    )
    db.add(new_user)
    details = {
        "created_username": payload.username,
        "role": payload.role,
        "is_verified": payload.is_verified,
        "admin": admin_user.username,
    }
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=tid,
            event_type="user_created_by_admin",
            severity="medium",
            timestamp=datetime.now(timezone.utc),
            actor_uid=admin_user.username,
            details=details,
            integrity_hash=compute_audit_hash(str(tid), "user_created_by_admin", "medium", details),
        )
    )
    await db.commit()
    await db.refresh(new_user)
    _sync_user_to_firebase(new_user)
    return _serialize_user(new_user)


@router.get("/overview")
async def get_admin_overview(
    db: AsyncSession = Depends(get_db),
    _admin: User = require_role("admin"),
) -> Dict[str, Any]:
    total_users = (await db.execute(select(func.count(User.id)))).scalar_one() or 0
    pending_users = (await db.execute(select(func.count(User.id)).where(User.is_verified.is_(False)))).scalar_one() or 0
    total_tenants = (await db.execute(select(func.count(Tenant.id)))).scalar_one() or 0
    total_threats = (await db.execute(select(func.count(ThreatAlert.id)))).scalar_one() or 0
    open_threats = (await db.execute(select(func.count(ThreatAlert.id)).where(ThreatAlert.status == "open"))).scalar_one() or 0

    fl_m = _read_live_metrics()
    return {
        "users": {"total": total_users, "verified": total_users - pending_users, "pending_verification": pending_users},
        "tenants": {"total": total_tenants, "isolation_mode": "Firestore Rules + Salted HKDF AES-256-GCM + ContextVar"},
        "threats": {"total": total_threats, "open": open_threats, "resolved": total_threats - open_threats},
        "fl": {
            "rounds_completed": fl_m.get("total_rounds_completed", 0),
            "accuracy": fl_m.get("latest_accuracy", 0.0),
            "privacy_epsilon": fl_m.get("privacy_epsilon_total", 0.0),
        },
    }
