"""
Pydantic v2 request and response schemas for SecureFL.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Generic, List, Literal, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Tenant schemas
# ---------------------------------------------------------------------------


class TenantBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Unique tenant name")


class TenantCreate(TenantBase):
    pass


class TenantResponse(TenantBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: Optional[str] = None
    created_at: datetime
    is_active: bool
    key_version: int = 1
    key_fingerprint: Optional[str] = None


class ArchiveEncryptRequest(BaseModel):
    archive_name: str = Field(..., min_length=1, max_length=128)
    payload: Dict[str, Any]


# ---------------------------------------------------------------------------
# Audit Log schemas
# ---------------------------------------------------------------------------


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    event_type: str
    severity: Literal["low", "medium", "high", "critical"]
    timestamp: datetime
    details: dict[str, Any] = Field(default_factory=dict)
    source_ip: Optional[str] = None
    actor_uid: Optional[str] = None
    integrity_hash: Optional[str] = None


# ---------------------------------------------------------------------------
# Threat Alert & ML Inference schemas
# ---------------------------------------------------------------------------


class ThreatAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    tenant_name: Optional[str] = None
    threat_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    anomaly_score: Optional[float] = None
    severity: Optional[str] = None
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    description: Optional[str] = None
    ml_model: Optional[str] = None
    xai_explanation: Optional[Dict[str, Any]] = None
    recommended_action: Optional[str] = None
    status: Literal["open", "acknowledged", "resolved"]
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None


class ThreatAlertSummary(BaseModel):
    total: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)


class TelemetryAnalyzeRequest(BaseModel):
    tenant_id: Optional[str] = None
    source_ip: Optional[str] = "10.0.1.50"
    destination_ip: Optional[str] = "10.0.0.10"
    model_type: Literal["lstm", "random_forest", "xgboost"] = "lstm"
    features: Dict[str, float]


# ---------------------------------------------------------------------------
# Federated Learning & Privacy schemas
# ---------------------------------------------------------------------------


class FLRoundResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    round_num: int
    strategy: str = "krum"
    accuracy: float
    loss: float
    privacy_epsilon: float
    timestamp: datetime
    participating_tenants: List[str] = Field(default_factory=list)
    rejected_tenants: List[str] = Field(default_factory=list)


class FLStatusResponse(BaseModel):
    current_round: int
    total_rounds: int
    is_training: bool
    connected_clients: int
    global_model_accuracy: float
    strategy: str = "krum"


class FLTriggerRequest(BaseModel):
    rounds: int = Field(default=1, ge=1, le=5)
    strategy: Literal["krum", "trimmed_mean", "fedavg"] = "krum"
    dp_noise_multiplier: float = Field(default=1.2, ge=0.1, le=10.0)
    inject_byzantine: bool = False


# ---------------------------------------------------------------------------
# Auth & User Governance schemas
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1)


class UserRegisterRequest(BaseModel):
    """Public registration schema — strictly forbids self-registering as 'admin'."""

    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8)
    email: Optional[str] = Field(None, max_length=255)
    full_name: Optional[str] = Field(None, max_length=255)
    tenant_id: Optional[str] = None
    role: Literal["user", "analyst"] = "user"


class FirebaseSyncRequest(BaseModel):
    id_token: str = Field(..., min_length=10)
    username: Optional[str] = None
    full_name: Optional[str] = None
    tenant_id: Optional[str] = None
    requested_role: Literal["user", "analyst"] = "user"


class PasswordResetRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    firebase_uid: Optional[str] = None
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    tenant_id: uuid.UUID
    tenant_name: Optional[str] = None
    role: str
    is_active: bool
    is_verified: bool
    is_restricted: bool = False
    created_at: Optional[datetime] = None
    verified_by: Optional[str] = None
    verified_at: Optional[datetime] = None


class UserVerifyAction(BaseModel):
    action: Literal["approve", "reject"]
    role: Optional[Literal["admin", "analyst", "user"]] = None
    tenant_id: Optional[str] = None


class UserStatusUpdate(BaseModel):
    is_active: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: str
    tenant_name: Optional[str] = None
    role: str
    username: str
    full_name: Optional[str] = None
    is_verified: bool = True
    auth_provider: str = "local_jwt"


# ---------------------------------------------------------------------------
# Security Response & Settings schemas
# ---------------------------------------------------------------------------


class SecurityResponseRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    alert_id: Optional[uuid.UUID] = None
    action_type: str
    target_subject: Optional[str] = None
    approval_status: str
    requires_approval: bool
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime


class ResponseApprovalAction(BaseModel):
    decision: Literal["approve", "reject"]
    note: Optional[str] = None


class SystemSettingsPayload(BaseModel):
    dp_epsilon_budget: float = Field(default=10.0, ge=0.5, le=50.0)
    dp_noise_multiplier: float = Field(default=1.2, ge=0.1, le=10.0)
    fl_strategy: Literal["krum", "trimmed_mean", "fedavg"] = "krum"
    krum_f: int = Field(default=1, ge=0, le=3)
    auto_block_high_confidence: bool = False
    rate_limit_auth_per_min: int = Field(default=20, ge=5, le=200)


# ---------------------------------------------------------------------------
# Paginated response
# ---------------------------------------------------------------------------


class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]
    total: int = Field(..., ge=0)
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)

    @field_validator("page_size")
    @classmethod
    def page_size_must_be_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("page_size must be >= 1")
        return v
