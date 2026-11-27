"""
Centralized configuration settings for the SecureFL Multi-Tenant Security Platform.
"""
from __future__ import annotations

import logging
import secrets
from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("SecureFL.Config")

# Ephemeral per-process fallback keys for development/test only (never static literals)
_EPHEMERAL_DEV_JWT_SECRET = secrets.token_hex(32)
_EPHEMERAL_DEV_MASTER_KEY = secrets.token_hex(32)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: str = "development"
    log_level: str = "INFO"

    # Firebase configuration
    firebase_enabled: bool = False
    firebase_use_emulator: bool = False
    firebase_project_id: str = ""
    firebase_storage_bucket: str = ""
    firebase_web_api_key: str = ""
    firebase_auth_domain: str = ""
    firebase_app_id: str = ""
    firebase_app_check_enforced: bool = False
    google_application_credentials: str = ""

    firebase_auth_emulator_host: str = "127.0.0.1:9099"
    firestore_emulator_host: str = "127.0.0.1:8085"
    firebase_storage_emulator_host: str = "127.0.0.1:9199"

    # Database fallback / hybrid local cache
    database_url: str = "sqlite+aiosqlite:///./multitenant.db"
    sqlalchemy_echo: bool = False

    # JWT & Security
    jwt_secret_key: str = ""
    secret_key: str = ""
    access_token_expire_minutes: int = 60
    algorithm: str = "HS256"

    # HKDF AES-256-GCM Encryption
    tenant_master_key: str = ""
    master_encryption_key: str = ""
    tenant_hkdf_salt: str = "securefl-hkdf-v2-salt"

    # CORS & Rate limiting
    cors_origins: str = (
        "http://localhost:8000,http://127.0.0.1:8000,"
        "http://localhost:5000,http://127.0.0.1:5000,"
        "http://localhost:3000"
    )
    rate_limit_auth_per_min: int = 20
    rate_limit_api_per_min: int = 120

    # Federated Learning & Differential Privacy
    fl_server_host: str = "127.0.0.1"
    fl_server_port: int = 8080
    fl_metrics_port: int = 8081
    fl_num_rounds: int = 5
    fl_min_clients: int = 5
    fl_strategy: str = "krum"
    fl_krum_f: int = 1
    fl_trim_beta: float = 0.1
    fl_tls_enabled: bool = False
    fl_tls_ca_cert: str = "./certs/ca.crt"
    fl_tls_server_cert: str = "./certs/server.crt"
    fl_tls_server_key: str = "./certs/server.key"

    privacy_epsilon_budget: float = 10.0
    privacy_delta: float = 1e-5
    dp_noise_multiplier: float = 1.2
    max_gradient_norm: float = 1.0

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() == "production"

    @property
    def effective_jwt_secret(self) -> str:
        raw = (self.jwt_secret_key or self.secret_key or "").strip()
        if raw:
            if len(raw) < 32 and self.is_production:
                raise RuntimeError("JWT_SECRET_KEY must be at least 32 characters in production.")
            return raw
        if self.is_production:
            raise RuntimeError("JWT_SECRET_KEY must be set when ENVIRONMENT=production.")
        return _EPHEMERAL_DEV_JWT_SECRET

    @property
    def effective_master_key_bytes(self) -> bytes:
        raw = (self.tenant_master_key or self.master_encryption_key or "").strip()
        if raw:
            try:
                key_bytes = bytes.fromhex(raw)
                if len(key_bytes) >= 32:
                    return key_bytes[:32]
            except ValueError:
                pass
            # Non-hex string passphrase -> SHA-256 32 bytes
            import hashlib
            return hashlib.sha256(raw.encode("utf-8")).digest()

        if self.is_production:
            raise RuntimeError(
                "TENANT_MASTER_KEY / MASTER_ENCRYPTION_KEY must be set when ENVIRONMENT=production."
            )
        return bytes.fromhex(_EPHEMERAL_DEV_MASTER_KEY)

    @property
    def hkdf_salt_bytes(self) -> bytes:
        return self.tenant_hkdf_salt.encode("utf-8")

    @property
    def cors_origins_list(self) -> List[str]:
        origins = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        if self.firebase_project_id and self.firebase_project_id != "your-firebase-project-id":
            origins.extend([
                f"https://{self.firebase_project_id}.web.app",
                f"https://{self.firebase_project_id}.firebaseapp.com",
            ])
        # Deduplicate while preserving order; reject wildcard "*" with credentials
        cleaned: List[str] = []
        for origin in origins:
            if origin != "*" and origin not in cleaned:
                cleaned.append(origin)
        return cleaned or ["http://localhost:8000", "http://127.0.0.1:8000"]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
