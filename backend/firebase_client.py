"""
Firebase Admin SDK integration supporting Cloud, Local Emulator Suite, and local fallback.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from .config import get_settings

logger = logging.getLogger("SecureFL.Firebase")


class FirebaseService:
    """Manages Firebase Admin initialization, Auth ID tokens, Firestore, Storage, and App Check."""

    def __init__(self) -> None:
        self._app = None
        self._firestore = None
        self._bucket = None
        self._mode: str = "local_fallback"
        self._last_error: Optional[str] = None
        self._initialized: bool = False

    def initialize(self) -> None:
        if self._initialized:
            return
        self._initialized = True

        settings = get_settings()
        if not settings.firebase_enabled and not settings.firebase_use_emulator:
            self._mode = "local_fallback"
            logger.info("Firebase disabled in config; running in local SQLite/artifact fallback mode.")
            return

        try:
            import firebase_admin
            from firebase_admin import credentials, firestore, storage
        except ImportError as exc:
            self._mode = "local_fallback"
            self._last_error = f"firebase-admin import error: {exc}"
            logger.warning(self._last_error)
            return

        # Configure emulator env vars when requested
        if settings.firebase_use_emulator:
            os.environ.setdefault("FIREBASE_AUTH_EMULATOR_HOST", settings.firebase_auth_emulator_host)
            os.environ.setdefault("FIRESTORE_EMULATOR_HOST", settings.firestore_emulator_host)
            os.environ.setdefault("FIREBASE_STORAGE_EMULATOR_HOST", settings.firebase_storage_emulator_host)
            os.environ.setdefault("GCLOUD_PROJECT", settings.firebase_project_id or "securefl-emulator")

        options: Dict[str, Any] = {}
        if settings.firebase_project_id and settings.firebase_project_id != "your-firebase-project-id":
            options["projectId"] = settings.firebase_project_id
        if settings.firebase_storage_bucket and "your-firebase-project-id" not in settings.firebase_storage_bucket:
            options["storageBucket"] = settings.firebase_storage_bucket

        try:
            if firebase_admin._apps:
                self._app = firebase_admin.get_app()
            else:
                cred_path = settings.google_application_credentials
                if cred_path and Path(cred_path).exists():
                    cred = credentials.Certificate(cred_path)
                    self._app = firebase_admin.initialize_app(cred, options or None)
                    self._mode = "emulator" if settings.firebase_use_emulator else "cloud"
                elif settings.firebase_use_emulator:
                    # Emulator works without a real service account JSON
                    self._app = firebase_admin.initialize_app(options=options or {"projectId": "securefl-emulator"})
                    self._mode = "emulator"
                else:
                    self._mode = "local_fallback"
                    self._last_error = (
                        "GOOGLE_APPLICATION_CREDENTIALS file not found and FIREBASE_USE_EMULATOR=false."
                    )
                    logger.warning("Firebase fallback active: %s", self._last_error)
                    return

            try:
                self._firestore = firestore.client(app=self._app)
            except Exception as fs_exc:
                self._last_error = f"Firestore client unavailable: {fs_exc}"
                logger.warning(self._last_error)

            if options.get("storageBucket"):
                try:
                    self._bucket = storage.bucket(app=self._app)
                except Exception as st_exc:
                    logger.info("Firebase Storage bucket unavailable (Spark fallback active): %s", st_exc)

            logger.info("Firebase initialized successfully in mode=%s", self._mode)
        except Exception as exc:
            self._mode = "local_fallback"
            self._last_error = str(exc)
            logger.warning("Firebase initialization failed, using local fallback: %s", exc)

    @property
    def mode(self) -> str:
        if not self._initialized:
            self.initialize()
        return self._mode

    @property
    def is_firebase_active(self) -> bool:
        return self.mode in ("cloud", "emulator") and self._app is not None

    @property
    def firestore_client(self):
        if not self._initialized:
            self.initialize()
        return self._firestore

    @property
    def storage_bucket(self):
        if not self._initialized:
            self.initialize()
        return self._bucket

    def status(self) -> Dict[str, Any]:
        settings = get_settings()
        return {
            "mode": self.mode,
            "firebase_enabled": settings.firebase_enabled,
            "emulator_mode": settings.firebase_use_emulator,
            "project_id": settings.firebase_project_id or "unconfigured",
            "auth_ready": self.is_firebase_active,
            "firestore_ready": self._firestore is not None,
            "storage_ready": self._bucket is not None,
            "storage_fallback": "local_encrypted_artifacts" if self._bucket is None else "firebase_storage",
            "functions_mode": "emulator_or_blaze_plus_local_fastapi_mirror",
            "app_check_enforced": settings.firebase_app_check_enforced,
            "last_error": self._last_error,
        }

    def verify_id_token(self, id_token: str, check_revoked: bool = True) -> Dict[str, Any]:
        if not self.is_firebase_active:
            raise RuntimeError("Firebase Auth is not active in local_fallback mode.")
        from firebase_admin import auth
        return auth.verify_id_token(id_token, app=self._app, check_revoked=check_revoked)

    def verify_app_check_token(self, token: str) -> Dict[str, Any]:
        if not self.is_firebase_active:
            raise RuntimeError("Firebase App Check is not active in local_fallback mode.")
        from firebase_admin import app_check
        return app_check.verify_token(token, app=self._app)

    def set_custom_claims(self, uid: str, claims: Dict[str, Any]) -> bool:
        if not self.is_firebase_active:
            return False
        from firebase_admin import auth
        auth.set_custom_user_claims(uid, claims, app=self._app)
        return True

    def create_auth_user(
        self, email: str, password: str, display_name: str
    ) -> Optional[str]:
        if not self.is_firebase_active:
            return None
        from firebase_admin import auth
        user_record = auth.create_user(
            email=email,
            password=password,
            display_name=display_name,
            email_verified=False,
            app=self._app,
        )
        return user_record.uid

    def revoke_refresh_tokens(self, uid: str) -> bool:
        if not self.is_firebase_active:
            return False
        from firebase_admin import auth
        auth.revoke_refresh_tokens(uid, app=self._app)
        return True

    def generate_password_reset_link(self, email: str) -> Optional[str]:
        if not self.is_firebase_active:
            return None
        from firebase_admin import auth
        return auth.generate_password_reset_link(email, app=self._app)


firebase_service = FirebaseService()
