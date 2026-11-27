"""
FastAPI Main Application for SecureFL — Multi-Tenant Cloud Security & Federated Learning.
"""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .auth import (
    create_access_token,
    get_current_user,
    hash_password,
    oauth2_scheme,
    parse_uuid,
    verify_local_jwt,
    verify_password,
)
from .config import get_settings
from .database import (
    AsyncSessionLocal,
    AuditLog,
    FLRound,
    ResponseHistory,
    RevokedToken,
    Tenant,
    ThreatAlert,
    User,
    get_db,
    init_db,
)
from .firebase_client import firebase_service
from .isolation import data_leakage_detector, tenant_key_vault
from .metrics import CROSS_TENANT_DENIED_TOTAL, prometheus_payload
from .middleware import (
    DataLeakageInspectionMiddleware,
    SecurityAndMetricsMiddleware,
    SlidingWindowRateLimitMiddleware,
    TenantIsolationMiddleware,
)
from .repositories import compute_audit_hash, firestore_repo
from .response_engine import record_failed_login_attempt
from .routers import admin, audit, cicd, federated, responses, system, tenants, threats
from .schemas import (
    FirebaseSyncRequest,
    LoginRequest,
    PasswordResetRequest,
    TokenResponse,
    UserRegisterRequest,
    UserResponse,
)

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] [SecureFL] %(message)s",
)
logger = logging.getLogger("SecureFL.Gateway")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def _on_data_leakage(ctx_tid: str, found_tid: str, _payload: Any) -> None:
    CROSS_TENANT_DENIED_TOTAL.labels(source="leakage_detector").inc()
    logger.critical("LEAKAGE ALERT: Context=%s Leaked=%s", ctx_tid, found_tid)


data_leakage_detector.register_leakage_callback(_on_data_leakage)


async def _seed_initial_data() -> None:
    """Seed 5 isolated tenants, baseline accounts, and initial threats non-destructively."""
    async with AsyncSessionLocal() as session:
        existing_tenants = {t.name: t for t in (await session.execute(select(Tenant))).scalars().all()}

        tenant_configs = [
            ("Tenant Alpha (E-Commerce)", "tenant-alpha"),
            ("Tenant Beta (Financial Services)", "tenant-beta"),
            ("Tenant Gamma (Cloud Core & CI/CD)", "tenant-gamma"),
            ("Tenant Delta (Healthcare Cloud)", "tenant-delta"),
            ("Tenant Epsilon (SaaS Enterprise)", "tenant-epsilon"),
        ]

        tenants_map: Dict[str, Tenant] = {}
        for name, slug in tenant_configs:
            if name in existing_tenants:
                t = existing_tenants[name]
                if not t.slug:
                    t.slug = slug
                if not t.key_fingerprint:
                    t.key_fingerprint = tenant_key_vault.key_fingerprint(str(t.id), version=t.key_version or 1)
                tenants_map[slug] = t
            else:
                tid = uuid.uuid4()
                fp = tenant_key_vault.key_fingerprint(str(tid), version=1)
                t = Tenant(
                    id=tid,
                    name=name,
                    slug=slug,
                    encryption_key="HKDF-MANAGED",
                    key_version=1,
                    key_fingerprint=fp,
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                )
                session.add(t)
                tenants_map[slug] = t

        await session.flush()

        t_alpha = tenants_map["tenant-alpha"]
        t_beta = tenants_map["tenant-beta"]
        t_gamma = tenants_map["tenant-gamma"]
        t_delta = tenants_map["tenant-delta"]
        t_epsilon = tenants_map["tenant-epsilon"]

        existing_users = {u.username: u for u in (await session.execute(select(User))).scalars().all()}

        core_users = [
            ("admin", "admin123", "Master System Admin", "admin@securefl.cloud", t_alpha.id, "admin", True),
            ("alpha_user", "user123", "Alice Alpha (E-Commerce Dev)", "alice@alpha-corp.io", t_alpha.id, "user", True),
            ("beta_user", "user123", "Bob Beta (Financial SecOps)", "bob@beta-bank.io", t_beta.id, "user", True),
            ("gamma_user", "user123", "Charlie Gamma (DevOps Core)", "charlie@gamma-cloud.io", t_gamma.id, "user", True),
            ("delta_user", "user123", "Diana Delta (Healthcare Sec)", "diana@delta-health.io", t_delta.id, "user", True),
            ("epsilon_user", "user123", "Evan Epsilon (SaaS Ops)", "evan@epsilon-saas.io", t_epsilon.id, "user", True),
            ("analyst_alpha", "analyst123", "Security Analyst Alpha", "analyst@alpha-corp.io", t_alpha.id, "analyst", True),
            ("pending_analyst", "pending123", "Sarah Connor", "s.connor@beta-bank.io", t_beta.id, "analyst", False),
        ]

        now = datetime.now(timezone.utc)
        for uname, pwd, full_name, email, tid, role, verified in core_users:
            if uname not in existing_users:
                session.add(
                    User(
                        id=uuid.uuid4(),
                        username=uname,
                        hashed_password=hash_password(pwd),
                        full_name=full_name,
                        email=email,
                        tenant_id=tid,
                        role=role,
                        is_active=True,
                        is_verified=verified,
                        created_at=now,
                        verified_by="admin" if verified else None,
                        verified_at=now if verified else None,
                    )
                )

        threat_count = (await session.execute(select(func.count(ThreatAlert.id)))).scalar_one() or 0
        if threat_count < 6:
            seeds = [
                (
                    t_alpha.id, "Brute Force Authentication", 0.94, "critical",
                    "185.220.101.5", "Rapid failed login sequence (32 attempts/min)",
                ),
                (
                    t_beta.id, "Data Exfiltration Attempt", 0.96, "critical",
                    "10.0.4.15", "Unusual outbound transfer (145MB) during off-peak hours",
                ),
                (
                    t_gamma.id, "Cross-Tenant Access Attempt", 0.99, "critical",
                    "10.244.1.42", "Cross-tenant boundary probe blocked by isolation guard",
                ),
                (
                    t_delta.id, "Privilege Escalation", 0.91, "critical",
                    "10.0.2.88", "Unauthorized IAM role assumption attempt",
                ),
                (
                    t_epsilon.id, "Compromised CI/CD Pipeline Secret", 0.95, "critical",
                    "10.244.2.19", "API token exposed inside pipeline commit diff",
                ),
                (
                    t_alpha.id, "SQL Injection Attempt", 0.87, "high",
                    "172.16.4.88", "Unsanitized SELECT payload detected in API logs",
                ),
            ]
            for tid, t_type, conf, sev, src_ip, desc in seeds:
                session.add(
                    ThreatAlert(
                        id=uuid.uuid4(),
                        tenant_id=tid,
                        threat_type=t_type,
                        confidence=conf,
                        anomaly_score=round(conf * 3.1, 3),
                        severity=sev,
                        source_ip=src_ip,
                        description=desc,
                        ml_model="LSTMThreatDetector",
                        recommended_action="restrict_account" if sev == "critical" else "notify_admin",
                        status="open",
                        timestamp=now,
                    )
                )

        audit_count = (await session.execute(select(func.count(AuditLog.id)))).scalar_one() or 0
        if audit_count < 3:
            for tid, etype, sev, det in [
                (t_alpha.id, "tenant_isolation_enforced", "low", {"action": "workspace_init", "enc": "AES-256-GCM"}),
                (t_gamma.id, "cross_tenant_probe_blocked", "critical", {"target_tenant": str(t_beta.id), "res": "DENIED"}),
                (t_beta.id, "user_registration_pending", "medium", {"username": "pending_analyst", "status": "pending"}),
            ]:
                session.add(
                    AuditLog(
                        id=uuid.uuid4(),
                        tenant_id=tid,
                        event_type=etype,
                        severity=sev,
                        timestamp=now,
                        details=det,
                        integrity_hash=compute_audit_hash(str(tid), etype, sev, det),
                    )
                )

        await session.commit()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logger.info("Initializing SecureFL database, Firebase Admin SDK, and isolation guards...")
    firebase_service.initialize()
    try:
        await init_db()
        await _seed_initial_data()
    except Exception as exc:
        logger.warning("Startup initialization note: %s", exc)
    yield
    logger.info("Shutting down SecureFL API Gateway...")


app = FastAPI(
    title="SecureFL — Multi-Tenant Cloud Security & Federated Learning Gateway",
    description=(
        "Firebase-backed zero-trust multi-tenant security platform with AES-256-GCM HKDF isolation, "
        "Flower Federated Learning, RDP Differential Privacy, Byzantine robustness, and Explainable AI."
    ),
    version="3.0.0",
    lifespan=lifespan,
)

# Middleware execution order (outermost added last)
app.add_middleware(DataLeakageInspectionMiddleware)
app.add_middleware(TenantIsolationMiddleware)
app.add_middleware(SlidingWindowRateLimitMiddleware)
app.add_middleware(SecurityAndMetricsMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Firebase-AppCheck"],
)


# ---------------------------------------------------------------------------
# Authentication Endpoints (Zero-Trust: No Admin Bypass)
# ---------------------------------------------------------------------------


@app.post("/api/v1/auth/register", tags=["Authentication"], status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegisterRequest, db: AsyncSession = Depends(get_db)):
    """Register a standard 'user' or 'analyst' in PENDING VERIFICATION status (admin prohibited)."""
    existing = (await db.execute(select(User).where(User.username == payload.username))).scalars().first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Username '{payload.username}' is already taken.")

    if payload.tenant_id:
        target_tid = parse_uuid(payload.tenant_id, "tenant_id")
        tenant = (await db.execute(select(Tenant).where(Tenant.id == target_tid, Tenant.is_active.is_(True)))).scalars().first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Selected tenant not found or inactive.")
    else:
        first_t = (await session_first_tenant(db))
        target_tid = first_t.id

    fb_uid = None
    if payload.email and firebase_service.is_firebase_active:
        try:
            fb_uid = firebase_service.create_auth_user(
                email=payload.email,
                password=payload.password,
                display_name=payload.full_name or payload.username,
            )
            firebase_service.set_custom_claims(
                fb_uid,
                {"role": payload.role, "tenant_id": str(target_tid), "is_verified": False, "is_active": True},
            )
        except Exception as exc:
            logger.debug("Firebase user sync skipped during register: %s", exc)

    now = datetime.now(timezone.utc)
    new_user = User(
        id=uuid.uuid4(),
        firebase_uid=fb_uid,
        username=payload.username,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        email=payload.email,
        tenant_id=target_tid,
        role=payload.role,  # Literal["user", "analyst"] — admin blocked by schema
        is_active=True,
        is_verified=False,
        created_at=now,
    )
    db.add(new_user)

    details = {"username": payload.username, "role_requested": payload.role, "email": payload.email}
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=target_tid,
            event_type="user_registration_pending",
            severity="medium",
            timestamp=now,
            actor_uid=payload.username,
            details=details,
            integrity_hash=compute_audit_hash(str(target_tid), "user_registration_pending", "medium", details),
        )
    )
    await db.commit()
    await db.refresh(new_user)

    firestore_repo.sync_user(
        fb_uid or str(new_user.id),
        {
            "uid": fb_uid or str(new_user.id),
            "username": new_user.username,
            "email": new_user.email,
            "displayName": new_user.full_name or new_user.username,
            "role": new_user.role,
            "tenantId": str(target_tid),
            "isVerified": False,
            "isActive": True,
            "createdAt": now.isoformat(),
        },
    )

    return {
        "status": "PENDING_VERIFICATION",
        "message": f"Account '{payload.username}' created and awaiting Administrator approval.",
        "user_id": str(new_user.id),
        "username": new_user.username,
        "is_verified": False,
    }


async def session_first_tenant(db: AsyncSession) -> Tenant:
    t_row = (await db.execute(select(Tenant).where(Tenant.is_active.is_(True)).limit(1))).scalars().first()
    if not t_row:
        raise HTTPException(status_code=500, detail="No active tenants found.")
    return t_row


@app.post("/api/v1/auth/login", response_model=TokenResponse, tags=["Authentication"])
async def login(payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    user = (
        await db.execute(select(User).options(selectinload(User.tenant)).where(User.username == payload.username))
    ).scalars().first()

    client_ip = request.client.host if request.client else None
    if not user or not verify_password(payload.password, user.hashed_password):
        await record_failed_login_attempt(db, user, payload.username, client_ip)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account has been deactivated.")
    if user.is_restricted:
        raise HTTPException(status_code=403, detail="Account temporarily restricted by security policy.")
    if not user.is_verified:
        raise HTTPException(
            status_code=403,
            detail="Account Pending Verification: Administrator approval is required before sign-in.",
        )

    user.failed_login_attempts = 0
    await db.commit()

    tenant_name = user.tenant.name if user.tenant else "System / Multi-Tenant"
    token = create_access_token(
        data={"sub": user.username},
        tenant_id=str(user.tenant_id),
        role=user.role,
    )
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        tenant_id=str(user.tenant_id),
        tenant_name=tenant_name,
        role=user.role,
        username=user.username,
        full_name=user.full_name or user.username,
        is_verified=user.is_verified,
        auth_provider="local_jwt",
    )


@app.post("/api/v1/auth/firebase-sync", tags=["Authentication"])
async def firebase_sync_session(
    payload: FirebaseSyncRequest,
    db: AsyncSession = Depends(get_db),
):
    """Verify a Firebase Auth ID Token and synchronize/authorize the tenant membership."""
    if not firebase_service.is_firebase_active:
        raise HTTPException(status_code=503, detail="Firebase Auth is not active on this backend.")

    try:
        claims = firebase_service.verify_id_token(payload.id_token, check_revoked=True)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"Invalid or revoked Firebase ID token: {exc}") from exc

    uid = claims.get("uid") or claims.get("sub")
    email = claims.get("email")
    user = (
        await db.execute(select(User).options(selectinload(User.tenant)).where(User.firebase_uid == uid))
    ).scalars().first()
    if user is None and email:
        user = (
            await db.execute(select(User).options(selectinload(User.tenant)).where(User.email == email))
        ).scalars().first()
        if user:
            user.firebase_uid = uid

    if user is None:
        tid = parse_uuid(payload.tenant_id, "tenant_id") if payload.tenant_id else (await session_first_tenant(db)).id
        uname = payload.username or (email.split("@")[0] if email else f"fb_{uid[:8]}")
        user = User(
            id=uuid.uuid4(),
            firebase_uid=uid,
            username=uname,
            hashed_password=hash_password(uuid.uuid4().hex),
            email=email,
            full_name=payload.full_name or claims.get("name") or uname,
            tenant_id=tid,
            role=payload.requested_role,
            is_active=True,
            is_verified=False,
            created_at=datetime.now(timezone.utc),
        )
        db.add(user)
        await db.commit()
        return {"status": "PENDING_VERIFICATION", "is_verified": False, "username": user.username}

    await db.commit()
    if not user.is_active or user.is_restricted:
        raise HTTPException(status_code=403, detail="Account is deactivated or restricted.")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Account Pending Verification by Administrator.")

    firebase_service.set_custom_claims(
        uid,
        {"role": user.role, "tenant_id": str(user.tenant_id), "is_verified": True, "is_active": True},
    )
    return {
        "status": "VERIFIED",
        "username": user.username,
        "role": user.role,
        "tenant_id": str(user.tenant_id),
        "tenant_name": user.tenant.name if user.tenant else "Tenant",
        "is_verified": True,
        "auth_provider": "firebase_auth",
    }


@app.post("/api/v1/auth/password-reset", tags=["Authentication"])
async def request_password_reset(payload: PasswordResetRequest, db: AsyncSession = Depends(get_db)):
    """Trigger Firebase password reset flow without leaking account existence."""
    user = (await db.execute(select(User).where(User.email == payload.email))).scalars().first()
    if user:
        if firebase_service.is_firebase_active:
            try:
                firebase_service.generate_password_reset_link(payload.email)
            except Exception as exc:
                logger.debug("Password reset link generation note: %s", exc)
        db.add(
            AuditLog(
                id=uuid.uuid4(),
                tenant_id=user.tenant_id,
                event_type="password_reset_requested",
                severity="low",
                timestamp=datetime.now(timezone.utc),
                actor_uid=user.username,
                details={"email": payload.email},
                integrity_hash=compute_audit_hash(str(user.tenant_id), "password_reset_requested", "low", {"email": payload.email}),
            )
        )
        await db.commit()
    return {"status": "ACCEPTED", "message": "If an account matches that email, password reset instructions have been initiated."}


@app.post("/api/v1/auth/logout", tags=["Authentication"])
async def logout(
    token: str = Depends(oauth2_scheme),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke active local JWT jti and Firebase refresh tokens."""
    try:
        claims = verify_local_jwt(token)
        jti = claims.get("jti")
        if jti:
            db.add(RevokedToken(jti=str(jti), username=current_user.username))
    except HTTPException:
        pass
    if current_user.firebase_uid:
        firebase_service.revoke_refresh_tokens(current_user.firebase_uid)
    await db.commit()
    return {"status": "LOGGED_OUT"}


@app.get("/api/v1/auth/public-tenants", tags=["Authentication"])
async def list_public_tenants(db: AsyncSession = Depends(get_db)):
    tenants_list = (
        await db.execute(select(Tenant).where(Tenant.is_active.is_(True)).order_by(Tenant.name.asc()))
    ).scalars().all()
    return [{"id": str(t.id), "name": t.name} for t in tenants_list]


@app.get("/api/v1/auth/me", response_model=UserResponse, tags=["Authentication"])
async def get_my_profile(current_user: User = Depends(get_current_user)):
    t_name = current_user.tenant.name if current_user.tenant else "System"
    return UserResponse(
        id=current_user.id,
        firebase_uid=current_user.firebase_uid,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        tenant_id=current_user.tenant_id,
        tenant_name=t_name,
        role=current_user.role,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        is_restricted=current_user.is_restricted,
        created_at=current_user.created_at,
        verified_by=current_user.verified_by,
        verified_at=current_user.verified_at,
    )


# ---------------------------------------------------------------------------
# Frontend & Static Asset Serving (Compatible with FastAPI + Firebase Hosting)
# ---------------------------------------------------------------------------

INDEX_HTML_PATH = FRONTEND_DIR / "index.html"

if (FRONTEND_DIR / "css").exists():
    app.mount("/css", StaticFiles(directory=str(FRONTEND_DIR / "css")), name="css")
if (FRONTEND_DIR / "js").exists():
    app.mount("/js", StaticFiles(directory=str(FRONTEND_DIR / "js")), name="js")
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def serve_root():
    if INDEX_HTML_PATH.exists():
        return FileResponse(str(INDEX_HTML_PATH))
    return JSONResponse({"status": "RUNNING", "message": "SecureFL API Gateway Running."})


@app.get("/dashboard", include_in_schema=False)
async def serve_dashboard():
    if INDEX_HTML_PATH.exists():
        return FileResponse(str(INDEX_HTML_PATH))
    raise HTTPException(status_code=404, detail="frontend/index.html not found")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# System, Health, Prometheus & Stats Endpoints
# ---------------------------------------------------------------------------


@app.get("/metrics", include_in_schema=False)
async def metrics_endpoint():
    data, content_type = prometheus_payload()
    return Response(content=data, media_type=content_type)


@app.get("/api/v1/info", tags=["System"])
async def root_info():
    return {
        "project": "SecureFL — Multi-Tenant Cloud Data Isolation via Federated Learning",
        "applied_domain": "Firebase Cloud + Local ML/FL DevSecOps CI/CD Platform",
        "status": "OPERATIONAL",
        "version": "3.0.0",
        "docs_url": "/docs",
        "firebase_mode": firebase_service.mode,
    }


@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "HEALTHY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "api_gateway": "UP",
            "database": "UP",
            "firebase_mode": firebase_service.mode,
            "isolation_engine": "ACTIVE",
            "ml_inference": "READY",
        },
    }


@app.get("/api/v1/stats", tags=["System"])
async def get_system_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from .routers.federated import _read_live_metrics

    if current_user.role == "admin":
        threats_count = (await db.execute(select(func.count(ThreatAlert.id)))).scalar_one() or 0
        tenants_count = (
            await db.execute(select(func.count(Tenant.id)).where(Tenant.is_active.is_(True)))
        ).scalar_one() or 0
        users_count = (await db.execute(select(func.count(User.id)))).scalar_one() or 0
        pending_users_count = (
            await db.execute(select(func.count(User.id)).where(User.is_verified.is_(False)))
        ).scalar_one() or 0
        pending_responses = (
            await db.execute(
                select(func.count(ResponseHistory.id)).where(ResponseHistory.approval_status == "pending")
            )
        ).scalar_one() or 0
    else:
        threats_count = (
            await db.execute(select(func.count(ThreatAlert.id)).where(ThreatAlert.tenant_id == current_user.tenant_id))
        ).scalar_one() or 0
        tenants_count = 1
        users_count = 1
        pending_users_count = 0
        pending_responses = (
            await db.execute(
                select(func.count(ResponseHistory.id)).where(
                    ResponseHistory.tenant_id == current_user.tenant_id,
                    ResponseHistory.approval_status == "pending",
                )
            )
        ).scalar_one() or 0

    latest_round = (await db.execute(select(FLRound).order_by(FLRound.round_num.desc()).limit(1))).scalars().first()
    if latest_round:
        rounds = latest_round.round_num
        accuracy = latest_round.accuracy
        eps = latest_round.privacy_epsilon
    else:
        fl_m = _read_live_metrics()
        rounds = fl_m.get("total_rounds_completed", 0)
        accuracy = float(fl_m.get("latest_accuracy", 0.0))
        eps = float(fl_m.get("privacy_epsilon_total", 0.0))

    return {
        "threats": threats_count,
        "tenants": tenants_count,
        "users": users_count,
        "pendingVerifications": pending_users_count,
        "pendingResponses": pending_responses,
        "flRounds": rounds,
        "flAccuracy": accuracy,
        "epsilonUsed": eps,
        "epsilonTotal": settings.privacy_epsilon_budget,
        "firebaseMode": firebase_service.mode,
    }


app.include_router(admin.router)
app.include_router(tenants.router)
app.include_router(threats.router)
app.include_router(federated.router)
app.include_router(audit.router)
app.include_router(cicd.router)
app.include_router(responses.router)
app.include_router(system.router)
