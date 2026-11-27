"""
Tenants Router — Strictly Enforced Isolation, Salted HKDF Fingerprints, & Encrypted Archives.

Raw encryption keys are NEVER stored in databases or exposed over HTTP.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user, parse_uuid, require_role
from ..database import AuditLog, FLRound, Tenant, ThreatAlert, User, get_db
from ..isolation import enforce_tenant_isolation, tenant_key_vault
from ..metrics import CROSS_TENANT_DENIED_TOTAL
from ..repositories import compute_audit_hash, firestore_repo
from ..schemas import ArchiveEncryptRequest, TenantCreate, TenantResponse
from ..storage_service import tenant_storage

router = APIRouter(prefix="/api/v1/tenants", tags=["Tenants"])


async def _get_tenant_or_404(tenant_id: str, db: AsyncSession) -> Tenant:
    tid = parse_uuid(tenant_id, "tenant_id")
    result = await db.execute(
        select(Tenant).where(Tenant.id == tid, Tenant.is_active.is_(True))
    )
    tenant = result.scalars().first()
    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id!r} not found.")
    return tenant


@router.get("/me/current", response_model=Dict[str, Any])
async def get_my_tenant(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Return isolated tenant metadata and non-reversible HKDF key fingerprint (never raw keys)."""
    tid_str = str(current_user.tenant_id)
    tenant = await _get_tenant_or_404(tid_str, db)
    key_ver = int(getattr(tenant, "key_version", 1) or 1)
    fingerprint = tenant_key_vault.key_fingerprint(tid_str, version=key_ver)
    return {
        "id": tid_str,
        "name": tenant.name,
        "slug": tenant.slug,
        "is_active": tenant.is_active,
        "created_at": tenant.created_at.isoformat(),
        "encryption_algorithm": "AES-256-GCM (HKDF-SHA256 Salted)",
        "key_version": key_ver,
        "key_fingerprint": fingerprint,
        "isolation_level": "Fail-Closed ContextVar + Firestore Rules + AAD-Bound AES-256-GCM",
        "role": current_user.role,
    }


@router.post("/me/rotate-key", response_model=Dict[str, Any])
async def rotate_my_tenant_key(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Rotate tenant HKDF key version and record cryptographic rotation audit entry."""
    tid_str = str(current_user.tenant_id)
    tenant = await _get_tenant_or_404(tid_str, db)
    new_ver, _ = tenant_key_vault.rotate_key(tid_str)
    new_fp = tenant_key_vault.key_fingerprint(tid_str, version=new_ver)
    tenant.key_version = new_ver
    tenant.key_fingerprint = new_fp

    details = {"key_version": new_ver, "key_fingerprint": new_fp, "rotated_by": current_user.username}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            event_type="tenant_key_rotated",
            severity="medium",
            timestamp=datetime.now(timezone.utc),
            actor_uid=current_user.username,
            details=details,
            integrity_hash=compute_audit_hash(tid_str, "tenant_key_rotated", "medium", details),
        )
    )
    await db.commit()
    firestore_repo.sync_tenant(tid_str, {"keyVersion": new_ver, "keyFingerprint": new_fp})
    return {"tenant_id": tid_str, "key_version": new_ver, "key_fingerprint": new_fp}


@router.post("/me/encrypt-archive", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_encrypted_archive(
    req: ArchiveEncryptRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Encrypt JSON telemetry/log archive with tenant-bound AES-256-GCM and store in Storage/local."""
    tid_str = str(current_user.tenant_id)
    raw = json.dumps(req.payload, indent=2, default=str).encode("utf-8")
    meta = tenant_storage.save_encrypted_archive(tid_str, req.archive_name, raw)

    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=current_user.tenant_id,
            event_type="encrypted_archive_created",
            severity="low",
            timestamp=datetime.now(timezone.utc),
            actor_uid=current_user.username,
            details=meta,
            integrity_hash=compute_audit_hash(tid_str, "encrypted_archive_created", "low", meta),
        )
    )
    await db.commit()
    return meta


@router.get("/me/archives", response_model=List[Dict[str, Any]])
async def list_my_archives(current_user: User = Depends(get_current_user)) -> List[Dict[str, Any]]:
    return tenant_storage.list_archives(str(current_user.tenant_id))


@router.get("/me/archives/{archive_name}", response_model=Dict[str, Any])
async def read_my_archive(
    archive_name: str,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    tid_str = str(current_user.tenant_id)
    try:
        raw = tenant_storage.read_encrypted_archive(tid_str, archive_name)
        return {"archive_name": archive_name, "tenant_id": tid_str, "decrypted_payload": json.loads(raw.decode("utf-8"))}
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/", response_model=List[TenantResponse])
async def list_tenants(
    db: AsyncSession = Depends(get_db),
    _admin: User = require_role("admin"),
) -> List[TenantResponse]:
    result = await db.execute(select(Tenant).order_by(Tenant.created_at.desc()))
    tenants = result.scalars().all()
    out = []
    for t in tenants:
        resp = TenantResponse.model_validate(t)
        resp.key_fingerprint = t.key_fingerprint or tenant_key_vault.key_fingerprint(str(t.id), version=t.key_version or 1)
        out.append(resp)
    return out


@router.post("/", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    payload: TenantCreate,
    db: AsyncSession = Depends(get_db),
    admin_user: User = require_role("admin"),
) -> TenantResponse:
    existing = (await db.execute(select(Tenant).where(Tenant.name == payload.name))).scalars().first()
    if existing:
        raise HTTPException(status_code=400, detail=f"A tenant named {payload.name!r} already exists.")

    tid = uuid.uuid4()
    slug = re.sub(r"[^a-z0-9]+", "-", payload.name.lower()).strip("-") or str(tid)[:8]
    fp = tenant_key_vault.key_fingerprint(str(tid), version=1)

    tenant = Tenant(
        id=tid,
        name=payload.name,
        slug=slug,
        created_at=datetime.now(timezone.utc),
        encryption_key="HKDF-MANAGED",
        key_version=1,
        key_fingerprint=fp,
        is_active=True,
    )
    db.add(tenant)
    await db.flush()

    details = {"tenant_name": tenant.name, "key_fingerprint": fp}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            event_type="tenant_created",
            severity="low",
            timestamp=datetime.now(timezone.utc),
            actor_uid=admin_user.username,
            details=details,
            integrity_hash=compute_audit_hash(str(tenant.id), "tenant_created", "low", details),
        )
    )
    await db.commit()
    await db.refresh(tenant)

    firestore_repo.sync_tenant(
        str(tenant.id),
        {
            "id": str(tenant.id),
            "name": tenant.name,
            "slug": slug,
            "isActive": True,
            "keyVersion": 1,
            "keyFingerprint": fp,
            "encryptionAlgo": "AES-256-GCM",
            "createdAt": tenant.created_at.isoformat(),
        },
    )
    return TenantResponse.model_validate(tenant)


@router.get("/{tenant_id}", response_model=TenantResponse)
@enforce_tenant_isolation(allow_admin=True)
async def get_tenant(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TenantResponse:
    if current_user.role != "admin" and str(current_user.tenant_id) != tenant_id:
        CROSS_TENANT_DENIED_TOTAL.labels(source="tenants_get").inc()
        raise HTTPException(status_code=403, detail="Cross-tenant access denied.")
    tenant = await _get_tenant_or_404(tenant_id, db)
    resp = TenantResponse.model_validate(tenant)
    ver = tenant.key_version or 1
    resp.key_fingerprint = tenant.key_fingerprint or tenant_key_vault.key_fingerprint(str(tenant.id), version=ver)
    return resp


@router.get("/{tenant_id}/stats", response_model=Dict[str, Any])
@enforce_tenant_isolation(allow_admin=True)
async def get_tenant_stats(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if current_user.role != "admin" and str(current_user.tenant_id) != tenant_id:
        CROSS_TENANT_DENIED_TOTAL.labels(source="tenants_stats").inc()
        raise HTTPException(status_code=403, detail="You may only access your own tenant stats.")

    tid = parse_uuid(tenant_id, "tenant_id")
    total_threats = (
        await db.execute(select(func.count()).select_from(ThreatAlert).where(ThreatAlert.tenant_id == tid))
    ).scalar_one()
    open_threats = (
        await db.execute(
            select(func.count())
            .select_from(ThreatAlert)
            .where(ThreatAlert.tenant_id == tid, ThreatAlert.status == "open")
        )
    ).scalar_one()
    last_round = (await db.execute(select(FLRound).order_by(FLRound.round_num.desc()).limit(1))).scalars().first()
    audit_count = (
        await db.execute(select(func.count()).select_from(AuditLog).where(AuditLog.tenant_id == tid))
    ).scalar_one()

    return {
        "tenant_id": tenant_id,
        "total_threats": total_threats,
        "open_threats": open_threats,
        "last_fl_round_accuracy": last_round.accuracy if last_round else 0.0,
        "audit_log_count": audit_count,
    }


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    admin_user: User = require_role("admin"),
) -> None:
    tenant = await _get_tenant_or_404(tenant_id, db)
    tenant.is_active = False
    details = {"tenant_name": tenant.name}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            event_type="tenant_deleted",
            severity="high",
            timestamp=datetime.now(timezone.utc),
            actor_uid=admin_user.username,
            details=details,
            integrity_hash=compute_audit_hash(str(tenant.id), "tenant_deleted", "high", details),
        )
    )
    await db.commit()
    firestore_repo.sync_tenant(str(tenant.id), {"isActive": False})
