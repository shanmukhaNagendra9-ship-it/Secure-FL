"""
SQLAlchemy 2.0 async local database layer (fallback & relational mirror for Firestore).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator, List, Optional, Type, TypeVar

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    Uuid,
    select,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .config import get_settings

UUID = Uuid
_settings = get_settings()
DATABASE_URL: str = _settings.database_url

if DATABASE_URL.startswith("sqlite"):
    engine = create_async_engine(
        DATABASE_URL,
        echo=_settings.sqlalchemy_echo,
    )
else:
    engine = create_async_engine(
        DATABASE_URL,
        echo=_settings.sqlalchemy_echo,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
    )

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    slug: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    # Deprecated column kept nullable/placeholder for backwards schema compat; raw keys never stored.
    encryption_key: Mapped[str] = mapped_column(String(64), nullable=False, default="HKDF-MANAGED")
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    key_fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="tenant", lazy="select")
    threat_alerts: Mapped[List["ThreatAlert"]] = relationship("ThreatAlert", back_populates="tenant", lazy="select")
    users: Mapped[List["User"]] = relationship("User", back_populates="tenant", lazy="select")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="low", index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    actor_uid: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    integrity_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="audit_logs")


class ThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    threat_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ml_model: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    xai_explanation: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    recommended_action: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="threat_alerts")


class FLRound(Base):
    __tablename__ = "fl_rounds"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    round_num: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    strategy: Mapped[str] = mapped_column(String(32), nullable=False, default="krum")
    accuracy: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    loss: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    privacy_epsilon: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    privacy_delta: Mapped[float] = mapped_column(Float, nullable=False, default=1e-5)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    participating_tenants: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    rejected_tenants: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    model_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    firebase_uid: Mapped[Optional[str]] = mapped_column(String(128), unique=True, nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="user")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_restricted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    verified_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="users")


class ResponseHistory(Base):
    __tablename__ = "response_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    alert_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_subject: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    approval_status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending", index=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )


class ModelMetric(Base):
    __tablename__ = "model_metrics"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    model_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(32), nullable=False, default="federated")
    accuracy: Mapped[float] = mapped_column(Float, nullable=False)
    precision: Mapped[float] = mapped_column(Float, nullable=False)
    recall: Mapped[float] = mapped_column(Float, nullable=False)
    f1_score: Mapped[float] = mapped_column(Float, nullable=False)
    fpr: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    confusion_matrix: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class PrivacyMetric(Base):
    __tablename__ = "privacy_metrics"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    round_num: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    accountant_type: Mapped[str] = mapped_column(String(32), nullable=False, default="RDP")
    noise_multiplier: Mapped[float] = mapped_column(Float, nullable=False)
    clip_norm: Mapped[float] = mapped_column(Float, nullable=False)
    round_epsilon: Mapped[float] = mapped_column(Float, nullable=False)
    cumulative_epsilon: Mapped[float] = mapped_column(Float, nullable=False)
    delta: Mapped[float] = mapped_column(Float, nullable=False, default=1e-5)
    budget_limit: Mapped[float] = mapped_column(Float, nullable=False, default=10.0)
    budget_exceeded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(128), primary_key=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, nullable=False)
    updated_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


ModelT = TypeVar("ModelT", bound=Base)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create missing tables and safely migrate existing SQLite columns."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        def _migrate(connection):
            migrations = {
                "tenants": [
                    ("slug", "VARCHAR(128)"),
                    ("key_version", "INTEGER DEFAULT 1 NOT NULL"),
                    ("key_fingerprint", "VARCHAR(128)"),
                ],
                "users": [
                    ("firebase_uid", "VARCHAR(128)"),
                    ("is_verified", "BOOLEAN DEFAULT 0 NOT NULL"),
                    ("is_restricted", "BOOLEAN DEFAULT 0 NOT NULL"),
                    ("failed_login_attempts", "INTEGER DEFAULT 0 NOT NULL"),
                    ("email", "VARCHAR(255)"),
                    ("full_name", "VARCHAR(255)"),
                    ("created_at", "DATETIME"),
                    ("verified_by", "VARCHAR(255)"),
                    ("verified_at", "DATETIME"),
                ],
                "threat_alerts": [
                    ("anomaly_score", "FLOAT"),
                    ("severity", "VARCHAR(16)"),
                    ("ml_model", "VARCHAR(64)"),
                    ("xai_explanation", "JSON"),
                    ("recommended_action", "VARCHAR(128)"),
                ],
                "audit_logs": [
                    ("actor_uid", "VARCHAR(128)"),
                    ("integrity_hash", "VARCHAR(64)"),
                ],
                "fl_rounds": [
                    ("strategy", "VARCHAR(32) DEFAULT 'krum' NOT NULL"),
                    ("rejected_tenants", "JSON"),
                ],
            }
            for table, cols in migrations.items():
                try:
                    res = connection.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
                    existing_cols = {col[1] for col in res}
                    for col_name, col_def in cols:
                        if col_name not in existing_cols:
                            connection.exec_driver_sql(
                                f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}"
                            )
                except Exception:
                    pass

        if DATABASE_URL.startswith("sqlite"):
            await conn.run_sync(_migrate)


def get_tenant_scoped_query(model: Type[ModelT], tenant_id: uuid.UUID):
    if not hasattr(model, "tenant_id"):
        raise AttributeError(f"Model {model.__name__!r} does not have a 'tenant_id' column.")
    return select(model).where(model.tenant_id == tenant_id)  # type: ignore[attr-defined]
