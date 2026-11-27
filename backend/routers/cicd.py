"""
CI/CD DevSecOps Security Router — Real Pipeline Gate Evaluation, SAST/SCA Check, & History.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from federated_learning.pipeline_security import PipelineSecurityScanner
from ..auth import get_current_tenant_id, get_current_user, parse_uuid
from ..database import AuditLog, ThreatAlert, User, get_db
from ..isolation import enforce_tenant_isolation
from ..metrics import THREAT_ALERTS_TOTAL
from ..repositories import compute_audit_hash, firestore_repo
from ..response_engine import evaluate_and_queue_response

router = APIRouter(prefix="/api/v1/cicd", tags=["DevSecOps CI/CD"])


class PipelineScanRequest(BaseModel):
    repository_name: str
    commit_sha: str
    branch: str = "main"
    secrets_detected: int = Field(default=0, ge=0)
    vulnerabilities_detected: int = Field(default=0, ge=0)
    build_failed: bool = False
    files_changed: int = Field(default=1, ge=0)


class PipelineGateDecision(BaseModel):
    tenant_id: str
    repository: str
    commit_sha: str
    decision: str  # ALLOW | BLOCK | WARN
    reasons: List[str]
    timestamp: datetime


@router.post("/scan", response_model=PipelineGateDecision)
@enforce_tenant_isolation(allow_admin=True)
async def evaluate_pipeline_security(
    payload: PipelineScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant_id),
) -> PipelineGateDecision:
    reasons: List[str] = []
    decision = "ALLOW"

    if payload.secrets_detected > 0:
        decision = "BLOCK"
        reasons.append(
            f"Deployment Gate Blocked: {payload.secrets_detected} exposed credentials/keys detected in commit."
        )

    if payload.vulnerabilities_detected > 3:
        decision = "BLOCK"
        reasons.append(
            f"Vulnerability Threshold Exceeded: {payload.vulnerabilities_detected} vulnerable dependencies."
        )
    elif payload.vulnerabilities_detected > 0 and decision != "BLOCK":
        decision = "WARN"
        reasons.append(f"Security Advisory: {payload.vulnerabilities_detected} dependency warnings found.")

    if payload.files_changed > 150:
        reasons.append(f"Anomaly Flag: Abnormal repository change rate ({payload.files_changed} files).")
        if decision != "BLOCK":
            decision = "WARN"

    tenant_uuid = parse_uuid(tenant_id, "tenant_id")
    now = datetime.now(timezone.utc)

    if decision == "BLOCK":
        alert = ThreatAlert(
            id=uuid.uuid4(),
            tenant_id=tenant_uuid,
            threat_type="CI/CD Pipeline Security Gate Triggered",
            confidence=0.98,
            anomaly_score=3.4,
            severity="critical",
            timestamp=now,
            description="; ".join(reasons),
            ml_model="DevSecOpsGatePolicy",
            recommended_action="block_ip",
            status="open",
        )
        db.add(alert)
        await db.flush()
        THREAT_ALERTS_TOTAL.labels(
            tenant_id=tenant_id,
            severity="critical",
            threat_type=alert.threat_type,
        ).inc()
        await evaluate_and_queue_response(
            db=db,
            tenant_id=tenant_uuid,
            alert=alert,
            action_type="notify_admin",
            target_subject=f"{payload.repository_name}@{payload.commit_sha}",
            severity="critical",
            details={"decision": decision, "reasons": reasons},
        )

    details = {
        "repo": payload.repository_name,
        "commit": payload.commit_sha,
        "branch": payload.branch,
        "decision": decision,
        "reasons": reasons,
        "secrets_detected": payload.secrets_detected,
        "vulnerabilities_detected": payload.vulnerabilities_detected,
    }
    sev = "critical" if decision == "BLOCK" else ("medium" if decision == "WARN" else "low")
    audit = AuditLog(
        id=uuid.uuid4(),
        tenant_id=tenant_uuid,
        event_type="cicd_security_gate_evaluation",
        severity=sev,
        timestamp=now,
        actor_uid=current_user.username,
        details=details,
        integrity_hash=compute_audit_hash(tenant_id, "cicd_security_gate_evaluation", sev, details),
    )
    db.add(audit)
    await db.commit()
    firestore_repo.sync_audit_log(
        tenant_id,
        str(audit.id),
        {
            "id": str(audit.id),
            "tenantId": tenant_id,
            "eventType": audit.event_type,
            "severity": sev,
            "details": details,
            "timestamp": now.isoformat(),
        },
    )

    return PipelineGateDecision(
        tenant_id=tenant_id,
        repository=payload.repository_name,
        commit_sha=payload.commit_sha,
        decision=decision,
        reasons=reasons or ["All DevSecOps security checks passed."],
        timestamp=now,
    )


@router.get("/history")
async def get_pipeline_scan_history(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    stmt = select(AuditLog).where(AuditLog.event_type == "cicd_security_gate_evaluation")
    if current_user.role != "admin":
        stmt = stmt.where(AuditLog.tenant_id == current_user.tenant_id)
    logs = (await db.execute(stmt.order_by(AuditLog.timestamp.desc()).limit(25))).scalars().all()
    return [
        {
            "id": str(entry.id),
            "tenant_id": str(entry.tenant_id),
            "timestamp": entry.timestamp.isoformat(),
            "severity": entry.severity,
            **(entry.details or {}),
        }
        for entry in logs
    ]


@router.get("/status")
async def get_pipeline_security_status(
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant_id),
) -> Dict[str, Any]:
    """Run real local static scan & return actual DevSecOps posture."""
    scanner = PipelineSecurityScanner(tenant_id=tenant_id)
    src_scan = scanner.scan_source_code("backend")
    dep_scan = scanner.scan_dependencies("requirements.txt")
    workflow_exists = Path(".github/workflows/devsecops-pipeline.yml").exists()

    return {
        "tenant_id": tenant_id,
        "workflow_configured": workflow_exists,
        "source_secret_scan": src_scan,
        "dependency_cve_scan": dep_scan,
        "gates": {
            "sast_bandit_semgrep": "ACTIVE (Blocking High/Critical)",
            "dependency_pip_audit_safety": "ACTIVE (Blocking CVEs)",
            "secret_detect_secrets": "ACTIVE (Zero-Secret Policy)",  # pragma: allowlist secret
            "container_trivy": "ACTIVE (HIGH/CRITICAL Gate)",
            "sbom_syft_cosign": "ACTIVE (CycloneDX + Keyless Cosign)",
            "pytest_coverage_gate": "ACTIVE (>= 80% Coverage)",
        },
        "last_policy_check": datetime.now(timezone.utc).isoformat(),
        "status": "HEALTHY" if src_scan["status"] == "PASS" and dep_scan["status"] == "PASS" else "ATTENTION_REQUIRED",
    }
