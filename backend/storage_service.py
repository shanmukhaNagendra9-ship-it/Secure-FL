"""
Tenant-isolated artifact storage supporting Firebase Storage and local AES-256-GCM fallback.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .firebase_client import firebase_service
from .isolation import decrypt_tenant_data, encrypt_tenant_data, tenant_key_vault

logger = logging.getLogger("SecureFL.Storage")

ARTIFACTS_ROOT = Path("artifacts")


def _safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name)
    return cleaned or "artifact.bin"


class TenantStorageService:
    """Handles encrypted archives and PDF/CSV security reports per tenant."""

    def save_encrypted_archive(
        self, tenant_id: str, archive_name: str, raw_bytes: bytes
    ) -> Dict[str, Any]:
        safe_name = _safe_filename(archive_name)
        if not safe_name.endswith(".enc"):
            safe_name = f"{safe_name}.enc"

        key = tenant_key_vault.derive_key(tenant_id)
        encrypted = encrypt_tenant_data(
            raw_bytes, key, associated_data=str(tenant_id).encode("utf-8")
        )
        storage_path = f"tenants/{tenant_id}/archives/{safe_name}"

        bucket = firebase_service.storage_bucket
        backend_used = "local_encrypted_fallback"
        if bucket is not None:
            try:
                blob = bucket.blob(storage_path)
                blob.upload_from_string(encrypted, content_type="application/octet-stream")
                backend_used = "firebase_storage"
            except Exception as exc:
                logger.warning("Firebase Storage upload failed, saving locally: %s", exc)

        # Always persist locally as well when in fallback/hybrid mode
        local_dir = ARTIFACTS_ROOT / "tenants" / str(tenant_id) / "archives"
        local_dir.mkdir(parents=True, exist_ok=True)
        local_file = local_dir / safe_name
        local_file.write_bytes(encrypted)

        return {
            "tenant_id": str(tenant_id),
            "filename": safe_name,
            "storage_path": storage_path,
            "backend": backend_used,
            "size_bytes": len(encrypted),
            "encryption": "AES-256-GCM",
            "key_fingerprint": tenant_key_vault.key_fingerprint(tenant_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def read_encrypted_archive(self, tenant_id: str, archive_name: str) -> bytes:
        safe_name = _safe_filename(archive_name)
        if not safe_name.endswith(".enc"):
            safe_name = f"{safe_name}.enc"

        local_file = ARTIFACTS_ROOT / "tenants" / str(tenant_id) / "archives" / safe_name
        encrypted: bytes
        if local_file.exists():
            encrypted = local_file.read_bytes()
        elif firebase_service.storage_bucket is not None:
            blob = firebase_service.storage_bucket.blob(f"tenants/{tenant_id}/archives/{safe_name}")
            if not blob.exists():
                raise FileNotFoundError(f"Archive {safe_name} not found for tenant {tenant_id}")
            encrypted = blob.download_as_bytes()
        else:
            raise FileNotFoundError(f"Archive {safe_name} not found for tenant {tenant_id}")

        key = tenant_key_vault.derive_key(tenant_id)
        return decrypt_tenant_data(
            encrypted, key, associated_data=str(tenant_id).encode("utf-8")
        )

    def list_archives(self, tenant_id: str) -> List[Dict[str, Any]]:
        local_dir = ARTIFACTS_ROOT / "tenants" / str(tenant_id) / "archives"
        items: List[Dict[str, Any]] = []
        if local_dir.exists():
            for fp in sorted(local_dir.glob("*.enc"), reverse=True):
                stat = fp.stat()
                items.append({
                    "filename": fp.name,
                    "storage_path": f"tenants/{tenant_id}/archives/{fp.name}",
                    "size_bytes": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    "encryption": "AES-256-GCM",
                })
        return items

    def save_report(
        self, tenant_id: str, filename: str, content: bytes, content_type: str
    ) -> Dict[str, Any]:
        safe_name = _safe_filename(filename)
        storage_path = f"tenants/{tenant_id}/reports/{safe_name}"
        backend_used = "local_fallback"

        bucket = firebase_service.storage_bucket
        if bucket is not None:
            try:
                blob = bucket.blob(storage_path)
                blob.upload_from_string(content, content_type=content_type)
                backend_used = "firebase_storage"
            except Exception as exc:
                logger.warning("Firebase Storage report upload failed: %s", exc)

        local_dir = ARTIFACTS_ROOT / "tenants" / str(tenant_id) / "reports"
        local_dir.mkdir(parents=True, exist_ok=True)
        (local_dir / safe_name).write_bytes(content)

        return {
            "storage_path": storage_path,
            "backend": backend_used,
            "size_bytes": len(content),
        }


tenant_storage = TenantStorageService()
