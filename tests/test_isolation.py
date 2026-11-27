"""
Real Multi-Tenant Data Isolation & AES-256-GCM Encryption Tests (No Stubs).
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi import HTTPException

from backend.isolation import (
    DataLeakageDetector,
    TenantKeyVault,
    clear_tenant_context,
    decrypt_tenant_data,
    encrypt_tenant_data,
    enforce_tenant_isolation,
    get_current_tenant_id,
    set_tenant_context,
)
from backend.storage_service import TenantStorageService


def test_context_set_get_clear():
    tokens = set_tenant_context("tenant_a")
    try:
        assert get_current_tenant_id() == "tenant_a"
    finally:
        clear_tenant_context(tokens)

    with pytest.raises(RuntimeError):
        get_current_tenant_id()


def test_hkdf_key_vault_derivation_and_rotation():
    vault = TenantKeyVault(master_key=b"\x11" * 32, salt=b"unit-test-salt")
    k_a1 = vault.derive_key("tenant_a")
    k_b1 = vault.derive_key("tenant_b")
    assert len(k_a1) == 32
    assert k_a1 != k_b1

    new_ver, k_a2 = vault.rotate_key("tenant_a")
    assert new_ver == 2
    assert k_a2 != k_a1
    assert vault.key_fingerprint("tenant_a") != vault.key_fingerprint("tenant_b")


def test_aes_256_gcm_roundtrip_and_aad_isolation():
    vault = TenantKeyVault(master_key=b"\x22" * 32, salt=b"unit-test-salt")
    k_a = vault.derive_key("tenant_a")
    k_b = vault.derive_key("tenant_b")

    plaintext = b"Sensitive tenant_a security telemetry record"
    ct = encrypt_tenant_data(plaintext, k_a, associated_data=b"tenant_a")
    assert ct != plaintext
    assert decrypt_tenant_data(ct, k_a, associated_data=b"tenant_a") == plaintext

    # Cross-tenant key fails
    with pytest.raises(ValueError):
        decrypt_tenant_data(ct, k_b, associated_data=b"tenant_a")

    # Wrong AAD fails even with same key
    with pytest.raises(ValueError):
        decrypt_tenant_data(ct, k_a, associated_data=b"tenant_b")


def test_fail_closed_enforce_tenant_isolation():
    @enforce_tenant_isolation
    async def read_tenant_secret(tenant_id: str) -> str:
        return f"ok:{tenant_id}"

    # No context -> fail-closed 401
    with pytest.raises(HTTPException) as exc_unauth:
        asyncio.run(read_tenant_secret("tenant_a"))
    assert exc_unauth.value.status_code == 401

    tokens = set_tenant_context("tenant_a")
    try:
        assert asyncio.run(read_tenant_secret("tenant_a")) == "ok:tenant_a"
        with pytest.raises(HTTPException) as exc_cross:
            asyncio.run(read_tenant_secret("tenant_b"))
        assert exc_cross.value.status_code == 403
    finally:
        clear_tenant_context(tokens)


def test_data_leakage_detector_catches_foreign_tenant():
    detector = DataLeakageDetector()
    events = []
    detector.register_leakage_callback(lambda ctx, found, _p: events.append((ctx, found)))

    tokens = set_tenant_context("tenant_a")
    try:
        assert detector.inspect({"tenant_id": "tenant_a", "items": [{"tenantId": "tenant_a"}]}) is False
        assert detector.inspect({"items": [{"tenantId": "tenant_b"}]}) is True
        assert events == [("tenant_a", "tenant_b")]
    finally:
        clear_tenant_context(tokens)


def test_encrypted_storage_archive_roundtrip(tmp_path: Path, monkeypatch):
    import backend.storage_service as ss_mod

    monkeypatch.setattr(ss_mod, "ARTIFACTS_ROOT", tmp_path)
    storage = TenantStorageService()
    meta = storage.save_encrypted_archive("tenant_a", "logs_snapshot", b'{"secret":"alpha"}')
    assert meta["encryption"] == "AES-256-GCM"
    assert storage.read_encrypted_archive("tenant_a", "logs_snapshot") == b'{"secret":"alpha"}'
    with pytest.raises((FileNotFoundError, ValueError)):
        storage.read_encrypted_archive("tenant_b", "logs_snapshot")
