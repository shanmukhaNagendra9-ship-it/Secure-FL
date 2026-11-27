# Database & Firestore Schema Reference

## 1. Cloud Firestore Collections (11 Core Collections)

| Collection Path | Key Fields | Rules / Isolation Policy |
|---|---|---|
| `users/{uid}` | `uid`, `username`, `email`, `displayName`, `role`, `tenantId`, `isVerified`, `isActive`, `isRestricted` | Self-read / admin read; self-register restricted to `role='user', isVerified=false`; admin/SDK updates privilege fields. |
| `tenants/{tenantId}` | `id`, `name`, `slug`, `isActive`, `keyVersion`, `keyFingerprint`, `encryptionAlgo` | Admin write; tenant members read own tenant only. Raw keys strictly forbidden. |
| `tenants/{tenantId}/members/{uid}` & `tenant_members/{uid}_{tenantId}` | `uid`, `tenantId`, `role`, `status`, `updatedAt` | Admin/SDK write; tenant user reads own membership. |
| `tenants/{tenantId}/threat_events/{eventId}` | `id`, `tenantId`, `threatLabel`, `threatType`, `severity`, `anomalyScore`, `confidence`, `mlModel`, `shapExplanation`, `recommendedAction`, `sourceIp`, `timestamp` | Read by `isTenantMember(tenantId)` or admin; Admin SDK / admin write only; delete denied. |
| `tenants/{tenantId}/security_alerts/{alertId}` | `id`, `tenantId`, `threatEventId`, `threatType`, `severity`, `confidence`, `status`, `requiresApproval`, `acknowledgedBy`, `timestamp` | Read by tenant members/admin; status transitions by tenant analyst/admin; delete denied. |
| `tenants/{tenantId}/audit_logs/{logId}` | `id`, `tenantId`, `actorUid`, `eventType`, `severity`, `sourceIp`, `details`, `integrityHash`, `timestamp` | Tenant-scoped read; **immutable** (Admin SDK create only; client create/update/delete denied). |
| `tenants/{tenantId}/response_history/{respId}` | `id`, `tenantId`, `alertId`, `actionType`, `targetSubject`, `approvalStatus`, `requiresApproval`, `approvedBy`, `timestamp` | Tenant analyst/admin read; admin approval gate required for execution. |
| `federated_rounds/{roundId}` | `roundNum`, `strategy`, `participatingClients`, `participatingTenants`, `rejectedTenants`, `accuracy`, `loss`, `modelPath`, `timestamp` | Verified user read; Admin SDK write only. |
| `model_metrics/{metricId}` | `modelName`, `scope`, `accuracy`, `precision`, `recall`, `f1_score`, `fpr`, `latency_ms`, `confusion_matrix`, `evaluatedAt` | Verified user read; Admin SDK write only. |
| `privacy_metrics/{roundId}` | `roundNum`, `accountantType`, `noiseMultiplier`, `clipNorm`, `roundEpsilon`, `cumulativeEpsilon`, `delta`, `budgetLimit`, `timestamp` | Verified user read; Admin SDK write only. |
| `system_settings/{settingId}` | `dp_epsilon_budget`, `dp_noise_multiplier`, `fl_strategy`, `krum_f`, `auto_block_high_confidence`, `rate_limit_auth_per_min` | Verified user read; admin write only. |

## 2. Local SQLite / PostgreSQL Fallback Mirror (`backend/database.py`)
Mirrors all collections in relational tables (`tenants`, `users`, `threat_alerts`, `audit_logs`, `fl_rounds`, `response_history`, `model_metrics`, `privacy_metrics`, `revoked_tokens`, `system_settings`) so local offline execution and automated `pytest` verification run without external dependencies.
