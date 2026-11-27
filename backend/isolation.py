"""
Multi-tenant data isolation enforcement and AES-256-GCM cryptography.

Provides:
- Coroutine-safe TenantContext via contextvars with mandatory token cleanup
- AES-256-GCM encryption/decryption per tenant with optional AAD tenant binding
- TenantKeyVault with salted HKDF-SHA256 key derivation & key versioning
- Fail-closed @enforce_tenant_isolation decorator
- DataLeakageDetector for recursive response payload scanning
"""
from __future__ import annotations

import base64
import functools
import hashlib
import inspect
import json
import logging
import secrets
from contextvars import ContextVar, Token
from typing import Any, Callable, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException, status

from .config import get_settings

logger = logging.getLogger("SecureFL.Isolation")

# ---------------------------------------------------------------------------
# Tenant context (ContextVar — coroutine-safe)
# ---------------------------------------------------------------------------

_tenant_context_var: ContextVar[Optional[str]] = ContextVar(
    "_tenant_context_var", default=None
)
_admin_context_var: ContextVar[bool] = ContextVar(
    "_admin_context_var", default=False
)


def set_tenant_context(tenant_id: str, is_admin: bool = False) -> Tuple[Token, Token]:
    """Set current tenant ID and admin privilege flag in coroutine-local context."""
    if not tenant_id:
        raise ValueError("tenant_id must not be empty")
    t_token = _tenant_context_var.set(str(tenant_id))
    a_token = _admin_context_var.set(bool(is_admin))
    return t_token, a_token


def get_current_tenant_id() -> str:
    """Return the tenant ID from coroutine context or raise RuntimeError."""
    value: Optional[str] = _tenant_context_var.get()
    if value is None:
        raise RuntimeError(
            "No tenant context is set. Call set_tenant_context() before accessing tenant data."
        )
    return value


def is_admin_context() -> bool:
    """Return True if the current coroutine context represents a verified global admin."""
    return bool(_admin_context_var.get())


def clear_tenant_context(tokens: Token | Tuple[Token, Token]) -> None:
    """Reset context variables cleanly using the token(s) from set_tenant_context."""
    if isinstance(tokens, tuple):
        t_token, a_token = tokens
        _tenant_context_var.reset(t_token)
        _admin_context_var.reset(a_token)
    else:
        _tenant_context_var.reset(tokens)


# ---------------------------------------------------------------------------
# AES-256-GCM encryption helpers
# ---------------------------------------------------------------------------

_GCM_NONCE_SIZE = 12  # 96-bit nonce per NIST SP 800-38D


def encrypt_tenant_data(
    data: bytes,
    tenant_key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Encrypt *data* with AES-256-GCM using a 32-byte *tenant_key* and optional AAD."""
    if len(tenant_key) != 32:
        raise ValueError(
            f"tenant_key must be exactly 32 bytes for AES-256; got {len(tenant_key)} bytes."
        )
    nonce = secrets.token_bytes(_GCM_NONCE_SIZE)
    aesgcm = AESGCM(tenant_key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=associated_data)
    return nonce + ciphertext


def decrypt_tenant_data(
    ciphertext: bytes,
    tenant_key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypt nonce-prefixed AES-256-GCM *ciphertext* and verify authentication tag & AAD."""
    if len(tenant_key) != 32:
        raise ValueError(
            f"tenant_key must be exactly 32 bytes for AES-256; got {len(tenant_key)} bytes."
        )
    if len(ciphertext) < _GCM_NONCE_SIZE + 16:
        raise ValueError("Ciphertext is too short to be valid AES-GCM output.")
    nonce = ciphertext[:_GCM_NONCE_SIZE]
    ct = ciphertext[_GCM_NONCE_SIZE:]
    aesgcm = AESGCM(tenant_key)
    try:
        return aesgcm.decrypt(nonce, ct, associated_data=associated_data)
    except Exception as exc:
        raise ValueError("Decryption failed — wrong tenant key, altered AAD, or corrupted data.") from exc


# ---------------------------------------------------------------------------
# TenantKeyVault (Salted HKDF-SHA256 + Key Versioning)
# ---------------------------------------------------------------------------


class TenantKeyVault:
    """
    Derives unique, versioned 32-byte AES-256 keys per tenant using salted HKDF-SHA256.
    Raw data encryption keys are NEVER stored in SQLite or Firestore.
    """

    def __init__(
        self,
        master_key: Optional[bytes] = None,
        salt: Optional[bytes] = None,
    ) -> None:
        settings = get_settings()
        self._master_key: bytes = master_key or settings.effective_master_key_bytes
        self._salt: bytes = salt if salt is not None else settings.hkdf_salt_bytes
        self._versions: Dict[str, int] = {}
        self._cache: Dict[Tuple[str, int], bytes] = {}

    def current_version(self, tenant_id: str) -> int:
        return self._versions.get(str(tenant_id), 1)

    def derive_key(self, tenant_id: str, version: Optional[int] = None) -> bytes:
        tid = str(tenant_id)
        ver = version if version is not None else self.current_version(tid)
        cache_key = (tid, ver)
        if cache_key in self._cache:
            return self._cache[cache_key]

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            info=f"securefl:tenant-dek:{tid}:v{ver}".encode("utf-8"),
        )
        key = hkdf.derive(self._master_key)
        self._cache[cache_key] = key
        return key

    def key_fingerprint(self, tenant_id: str, version: Optional[int] = None) -> str:
        """Return non-reversible SHA-256 fingerprint for display/metadata only."""
        key = self.derive_key(tenant_id, version=version)
        digest = hashlib.sha256(key).hexdigest()[:16]
        ver = version if version is not None else self.current_version(str(tenant_id))
        return f"SHA256-v{ver}:{digest}"

    def rotate_key(self, tenant_id: str) -> Tuple[int, bytes]:
        """Increment key version for *tenant_id* and derive the new DEK."""
        tid = str(tenant_id)
        new_ver = self.current_version(tid) + 1
        self._versions[tid] = new_ver
        new_key = self.derive_key(tid, version=new_ver)
        return new_ver, new_key

    def encrypt_payload(self, tenant_id: str, payload: Dict[str, Any]) -> str:
        """Encrypt a JSON payload bound via AAD to *tenant_id* and return base64 token."""
        tid = str(tenant_id)
        ver = self.current_version(tid)
        key = self.derive_key(tid, version=ver)
        raw = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
        ct = encrypt_tenant_data(raw, key, associated_data=tid.encode("utf-8"))
        envelope = {"v": ver, "ct": base64.b64encode(ct).decode("ascii")}
        return json.dumps(envelope, separators=(",", ":"))

    def decrypt_payload(self, tenant_id: str, sealed_envelope: str) -> Dict[str, Any]:
        """Decrypt an envelope encrypted for *tenant_id*, verifying AAD & GCM tag."""
        tid = str(tenant_id)
        envelope = json.loads(sealed_envelope)
        ver = int(envelope["v"])
        ct = base64.b64decode(envelope["ct"])
        key = self.derive_key(tid, version=ver)
        plaintext = decrypt_tenant_data(ct, key, associated_data=tid.encode("utf-8"))
        return json.loads(plaintext.decode("utf-8"))


tenant_key_vault = TenantKeyVault()


# ---------------------------------------------------------------------------
# Fail-closed @enforce_tenant_isolation decorator
# ---------------------------------------------------------------------------


def enforce_tenant_isolation(
    func: Optional[Callable] = None, *, allow_admin: bool = False
) -> Callable:
    """
    Fail-closed tenant isolation decorator for async endpoints/services.

    - Requires an active ContextVar tenant context (raises HTTP 401 if absent).
    - Compares *tenant_id* parameter against the active tenant context (raises HTTP 403 on mismatch),
      unless *allow_admin=True* and the caller holds a verified global admin context.
    """

    def decorator(fn: Callable) -> Callable:
        sig = inspect.signature(fn)
        param_names = list(sig.parameters.keys())

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            call_tenant_id: Optional[str] = None
            if "tenant_id" in kwargs and kwargs["tenant_id"] is not None:
                call_tenant_id = str(kwargs["tenant_id"])
            elif "tenant_id" in param_names:
                idx = param_names.index("tenant_id")
                if idx < len(args) and args[idx] is not None:
                    call_tenant_id = str(args[idx])

            try:
                ctx_tenant_id = get_current_tenant_id()
            except RuntimeError as exc:
                logger.warning("Fail-closed isolation denial in %s(): no context set", fn.__qualname__)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Tenant security context is missing.",
                ) from exc

            if allow_admin and is_admin_context():
                return await fn(*args, **kwargs)

            if call_tenant_id is not None and call_tenant_id != ctx_tenant_id:
                logger.error(
                    "TENANT ISOLATION VIOLATION in %s(): target=%s, context=%s",
                    fn.__qualname__,
                    call_tenant_id,
                    ctx_tenant_id,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cross-tenant data access is not permitted.",
                )

            return await fn(*args, **kwargs)

        return wrapper

    if func is not None:
        return decorator(func)
    return decorator


# ---------------------------------------------------------------------------
# DataLeakageDetector
# ---------------------------------------------------------------------------


class DataLeakageDetector:
    """Inspects response payloads for cross-tenant data leakage."""

    def __init__(self) -> None:
        self._leakage_callbacks: list[Callable[[str, str, Any], None]] = []

    def register_leakage_callback(
        self, callback: Callable[[str, str, Any], None]
    ) -> None:
        self._leakage_callbacks.append(callback)

    def _fire_callbacks(
        self, context_tenant_id: str, found_tenant_id: str, payload: Any
    ) -> None:
        for cb in self._leakage_callbacks:
            try:
                cb(context_tenant_id, found_tenant_id, payload)
            except Exception:
                logger.exception("DataLeakageDetector callback failed")

    def inspect(self, payload: Any, raise_on_leakage: bool = False) -> bool:
        try:
            context_tid = get_current_tenant_id()
        except RuntimeError:
            return False

        if is_admin_context():
            return False

        return self._scan(payload, context_tid, raise_on_leakage)

    def _scan(self, node: Any, context_tid: str, raise_on_leakage: bool) -> bool:
        if isinstance(node, dict):
            for key in ("tenant_id", "tenantId", "tenant-id"):
                if key in node and node[key] is not None:
                    found = str(node[key])
                    if found and found != context_tid:
                        logger.error(
                            "DATA LEAKAGE DETECTED: response contains tenant_id=%s "
                            "while active tenant context=%s",
                            found,
                            context_tid,
                        )
                        self._fire_callbacks(context_tid, found, node)
                        if raise_on_leakage:
                            raise RuntimeError(
                                f"Cross-tenant data leakage detected: expected {context_tid}, found {found}"
                            )
                        return True
            for v in node.values():
                if self._scan(v, context_tid, raise_on_leakage):
                    return True
        elif isinstance(node, (list, tuple)):
            for item in node:
                if self._scan(item, context_tid, raise_on_leakage):
                    return True
        return False


data_leakage_detector = DataLeakageDetector()
