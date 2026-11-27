"""
Zero-Trust Authentication & RBAC for SecureFL.

Supports:
1. Firebase Authentication ID Token verification (verify_id_token with check_revoked=True)
   + optional Firebase App Check verification
2. Hardened HS256 JWT local/test fallback with explicit JTI revocation checking
3. Strict admin verification enforcement for ALL roles (zero self-registration admin bypass)
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import PyJWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .config import get_settings
from .database import RevokedToken, User, get_db
from .firebase_client import firebase_service

logger = logging.getLogger("SecureFL.Auth")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def parse_uuid(value: str, field_name: str = "id") -> uuid.UUID:
    """Parse a UUID string or raise HTTP 400 cleanly."""
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {field_name} UUID format.",
        ) from exc


def hash_password(plain_password: str) -> str:
    """Return bcrypt hash of *plain_password*."""
    pwd_bytes = plain_password[:72].encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return True if *plain_password* matches *hashed_password*."""
    try:
        pwd_bytes = plain_password[:72].encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(
    data: Dict[str, Any],
    tenant_id: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed HS256 JWT access token with unique jti."""
    settings = get_settings()
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update(
        {
            "tenant_id": str(tenant_id),
            "role": role,
            "exp": expire,
            "iat": now,
            "jti": str(uuid.uuid4()),
        }
    )
    return jwt.encode(to_encode, settings.effective_jwt_secret, algorithm=settings.algorithm)


def verify_local_jwt(token: str) -> Dict[str, Any]:
    """Decode and validate a local HS256 JWT token."""
    settings = get_settings()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload: Dict[str, Any] = jwt.decode(
            token, settings.effective_jwt_secret, algorithms=[settings.algorithm]
        )
        if not payload.get("sub"):
            raise credentials_exception
        return payload
    except PyJWTError as exc:
        raise credentials_exception from exc


def decode_bearer_claims_sync(token: str) -> Optional[Dict[str, Any]]:
    """
    Best-effort synchronous claim extractor for request context middleware.
    Supports Firebase ID tokens when active and local HS256 JWTs.
    """
    if firebase_service.is_firebase_active:
        try:
            claims = firebase_service.verify_id_token(token, check_revoked=True)
            return {
                "sub": claims.get("uid"),
                "tenant_id": claims.get("tenant_id"),
                "role": claims.get("role", "user"),
                "firebase": True,
            }
        except Exception:
            pass
    try:
        return verify_local_jwt(token)
    except HTTPException:
        return None


async def verify_app_check_if_enforced(request: Request) -> None:
    """Verify X-Firebase-AppCheck header when FIREBASE_APP_CHECK_ENFORCED=true."""
    settings = get_settings()
    if not settings.firebase_app_check_enforced or not firebase_service.is_firebase_active:
        return
    token = request.headers.get("X-Firebase-AppCheck", "").strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Firebase App Check token.",
        )
    try:
        firebase_service.verify_app_check_token(token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Firebase App Check token.",
        ) from exc


async def _resolve_firebase_user(
    claims: Dict[str, Any], db: AsyncSession
) -> User:
    uid = claims.get("uid") or claims.get("sub")
    email = claims.get("email")

    stmt = (
        select(User)
        .options(selectinload(User.tenant))
        .where(User.firebase_uid == uid)
    )
    user = (await db.execute(stmt)).scalars().first()
    if user is None and email:
        stmt_email = (
            select(User)
            .options(selectinload(User.tenant))
            .where(User.email == email)
        )
        user = (await db.execute(stmt_email)).scalars().first()
        if user is not None and not user.firebase_uid:
            user.firebase_uid = uid
            await db.flush()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Firebase account is not registered or linked to a tenant workspace.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def resolve_user_from_token(token: str, db: AsyncSession) -> User:
    """
    Verify either a Firebase ID token (when Firebase is active) or a local JWT,
    enforce revocation checks, and verify active + verified + unrestricted status.
    """
    user: Optional[User] = None

    if firebase_service.is_firebase_active:
        try:
            claims = firebase_service.verify_id_token(token, check_revoked=True)
            user = await _resolve_firebase_user(claims, db)
        except HTTPException:
            raise
        except Exception:
            # Fall through to local JWT verification only if token isn't Firebase RS256
            user = None

    if user is None:
        payload = verify_local_jwt(token)
        jti = payload.get("jti")
        if jti:
            revoked = (
                await db.execute(select(RevokedToken).where(RevokedToken.jti == str(jti)))
            ).scalars().first()
            if revoked is not None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        username = payload.get("sub")
        res = await db.execute(
            select(User)
            .options(selectinload(User.tenant))
            .where(User.username == username)
        )
        user = res.scalars().first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact your administrator.",
        )

    if user.is_restricted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is temporarily restricted by Security Response Policy.",
        )

    # Zero-trust: NEVER exempt any role (including admin) from verification!
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is pending verification by an administrator.",
        )

    return user


async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    await verify_app_check_if_enforced(request)
    return await resolve_user_from_token(token, db)


async def get_current_tenant_id(
    current_user: User = Depends(get_current_user),
) -> str:
    return str(current_user.tenant_id)


def require_role(*roles: str) -> Callable:
    async def _role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient permissions. Required role(s): {', '.join(roles)}. "
                    f"Your role: {current_user.role}."
                ),
            )
        return current_user

    return Depends(_role_checker)
