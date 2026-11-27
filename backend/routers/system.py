"""
Firebase Status, Client Config, and System Settings Router.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user, require_role
from ..config import get_settings
from ..database import SystemSetting, User, get_db
from ..firebase_client import firebase_service
from ..repositories import firestore_repo
from ..schemas import SystemSettingsPayload

router = APIRouter(prefix="/api/v1", tags=["Firebase & System Settings"])


@router.get("/firebase/status")
async def get_firebase_status(_current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Return live Firebase Cloud / Emulator / Spark fallback status."""
    return firebase_service.status()


@router.get("/firebase/client-config")
async def get_firebase_client_config() -> Dict[str, Any]:
    """
    Expose public Web SDK configuration (no server secrets ever).
    Allows Firebase Hosting and local FastAPI dashboard to initialize Web SDK cleanly.
    """
    settings = get_settings()
    configured = bool(
        settings.firebase_enabled
        and settings.firebase_web_api_key
        and settings.firebase_web_api_key != "your-firebase-web-api-key"  # pragma: allowlist secret
    )
    return {
        "enabled": configured or settings.firebase_use_emulator,
        "useEmulator": settings.firebase_use_emulator,
        "emulatorHosts": {
            "auth": settings.firebase_auth_emulator_host,
            "firestore": settings.firestore_emulator_host,
            "storage": settings.firebase_storage_emulator_host,
        },
        "firebaseConfig": {
            "apiKey": settings.firebase_web_api_key if configured else "",
            "authDomain": settings.firebase_auth_domain,
            "projectId": settings.firebase_project_id,
            "storageBucket": settings.firebase_storage_bucket,
            "appId": settings.firebase_app_id,
        },
    }


@router.get("/settings")
async def get_system_settings(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    row = (await db.execute(select(SystemSetting).where(SystemSetting.key == "platform_policy"))).scalars().first()
    if row:
        return row.value
    settings = get_settings()
    return {
        "dp_epsilon_budget": settings.privacy_epsilon_budget,
        "dp_noise_multiplier": settings.dp_noise_multiplier,
        "fl_strategy": settings.fl_strategy,
        "krum_f": settings.fl_krum_f,
        "auto_block_high_confidence": False,
        "rate_limit_auth_per_min": settings.rate_limit_auth_per_min,
    }


@router.put("/settings")
async def update_system_settings(
    payload: SystemSettingsPayload,
    db: AsyncSession = Depends(get_db),
    admin_user: User = require_role("admin"),
) -> Dict[str, Any]:
    data = payload.model_dump()
    now = datetime.now(timezone.utc)
    row = (await db.execute(select(SystemSetting).where(SystemSetting.key == "platform_policy"))).scalars().first()
    if row:
        row.value = data
        row.updated_by = admin_user.username
        row.updated_at = now
    else:
        db.add(SystemSetting(key="platform_policy", value=data, updated_by=admin_user.username, updated_at=now))
    await db.commit()
    firestore_repo.sync_system_setting("platform_policy", {**data, "updatedBy": admin_user.username, "updatedAt": now.isoformat()})
    return {"status": "UPDATED", "settings": data}
