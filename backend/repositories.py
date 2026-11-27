"""
Cloud Firestore 11-Collection Repository Mirror & Audit Integrity Helpers.

When Firebase is connected (Cloud or Emulator), every write is persisted into
the structured Firestore collection hierarchy alongside the local SQLite mirror.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .firebase_client import firebase_service

logger = logging.getLogger("SecureFL.Repository")


def compute_audit_hash(
    tenant_id: str, event_type: str, severity: str, details: Optional[Dict[str, Any]]
) -> str:
    canonical = json.dumps(
        {
            "tenant_id": str(tenant_id),
            "event_type": event_type,
            "severity": severity,
            "details": details or {},
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class FirestoreSyncRepository:
    """Best-effort async-safe sync writer to Cloud Firestore 11 collections."""

    @staticmethod
    def _db():
        return firebase_service.firestore_client

    @classmethod
    def sync_user(cls, uid: str, data: Dict[str, Any]) -> None:
        db = cls._db()
        if db is None:
            return
        try:
            db.collection("users").document(str(uid)).set(data, merge=True)
            tid = data.get("tenantId")
            if tid:
                member_doc = {
                    "uid": str(uid),
                    "tenantId": str(tid),
                    "role": data.get("role", "user"),
                    "status": "restricted" if data.get("isRestricted") else ("active" if data.get("isVerified") else "pending"),
                    "updatedAt": datetime.now(timezone.utc),
                }
                db.collection("tenants").document(str(tid)).collection("members").document(str(uid)).set(
                    member_doc, merge=True
                )
                db.collection("tenant_members").document(f"{uid}_{tid}").set(member_doc, merge=True)
        except Exception as exc:
            logger.debug("Firestore sync_user skipped: %s", exc)

    @classmethod
    def sync_tenant(cls, tenant_id: str, data: Dict[str, Any]) -> None:
        db = cls._db()
        if db is None:
            return
        try:
            safe_data = {k: v for k, v in data.items() if "encryption_key" not in k and "encryptionKey" not in k}
            db.collection("tenants").document(str(tenant_id)).set(safe_data, merge=True)
        except Exception as exc:
            logger.debug("Firestore sync_tenant skipped: %s", exc)

    @classmethod
    def sync_threat_event(cls, tenant_id: str, event_id: str, data: Dict[str, Any]) -> None:
        db = cls._db()
        if db is None:
            return
        try:
            db.collection("tenants").document(str(tenant_id)).collection("threat_events").document(
                str(event_id)
            ).set(data, merge=True)
        except Exception as exc:
            logger.debug("Firestore sync_threat_event skipped: %s", exc)

    @classmethod
    def sync_security_alert(cls, tenant_id: str, alert_id: str, data: Dict[str, Any]) -> None:
        db = cls._db()
        if db is None:
            return
        try:
            db.collection("tenants").document(str(tenant_id)).collection("security_alerts").document(
                str(alert_id)
            ).set(data, merge=True)
        except Exception as exc:
            logger.debug("Firestore sync_security_alert skipped: %s", exc)

    @classmethod
    def sync_audit_log(cls, tenant_id: str, log_id: str, data: Dict[str, Any]) -> None:
        db = cls._db()
        if db is None:
            return
        try:
            db.collection("tenants").document(str(tenant_id)).collection("audit_logs").document(
                str(log_id)
            ).set(data)
        except Exception as exc:
            logger.debug("Firestore sync_audit_log skipped: %s", exc)

    @classmethod
    def sync_response_history(cls, tenant_id: str, resp_id: str, data: Dict[str, Any]) -> None:
        db = cls._db()
        if db is None:
            return
        try:
            db.collection("tenants").document(str(tenant_id)).collection("response_history").document(
                str(resp_id)
            ).set(data, merge=True)
        except Exception as exc:
            logger.debug("Firestore sync_response_history skipped: %s", exc)

    @classmethod
    def sync_fl_round(cls, round_num: int, data: Dict[str, Any]) -> None:
        db = cls._db()
        if db is None:
            return
        try:
            db.collection("federated_rounds").document(f"round_{round_num}").set(data, merge=True)
        except Exception as exc:
            logger.debug("Firestore sync_fl_round skipped: %s", exc)

    @classmethod
    def sync_privacy_metric(cls, round_num: int, data: Dict[str, Any]) -> None:
        db = cls._db()
        if db is None:
            return
        try:
            db.collection("privacy_metrics").document(f"round_{round_num}").set(data, merge=True)
        except Exception as exc:
            logger.debug("Firestore sync_privacy_metric skipped: %s", exc)

    @classmethod
    def sync_model_metric(cls, metric_id: str, data: Dict[str, Any]) -> None:
        db = cls._db()
        if db is None:
            return
        try:
            db.collection("model_metrics").document(str(metric_id)).set(data, merge=True)
        except Exception as exc:
            logger.debug("Firestore sync_model_metric skipped: %s", exc)

    @classmethod
    def sync_system_setting(cls, key: str, data: Dict[str, Any]) -> None:
        db = cls._db()
        if db is None:
            return
        try:
            db.collection("system_settings").document(str(key)).set(data, merge=True)
        except Exception as exc:
            logger.debug("Firestore sync_system_setting skipped: %s", exc)


firestore_repo = FirestoreSyncRepository()
