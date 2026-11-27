# Firebase Cloud Architecture & Cost-Aware Hybrid Design

**Target Platform:** Firebase Managed Cloud Backend + Local Python/Docker Compute for ML & Flower FL  
**Constraint:** Zero paid dedicated server / VPS / EC2 required; Spark-plan compatible core deployment with explicit handling of Blaze-gated services.

---

## 1. High-Level Hybrid Architecture

```
+-----------------------------------------------------------------------------+
|                        CLIENT LAYER (HTTPS / SPA)                           |
|   Firebase Hosting  <--->  Dashboard (Dark Navy/Violet Glassmorphism UI)    |
|   - Firebase Web SDK (Auth, Firestore Realtime Listeners, Storage, AppCheck)|
+------------------+-------------------------+------------------------+-------+
                   | ID Token + App Check    | Firestore SDK          | Storage SDK
                   v                         v                        v
+----------------------------------+  +---------------------+  +--------------+
|  FIREBASE MANAGED CLOUD          |  | CLOUD FIRESTORE     |  | FIREBASE     |
|  - Firebase Authentication       |  | (11 Collections,    |  | STORAGE      |
|    (Email/Pass, Reset, Claims)   |  |  Tenant-Scoped      |  | - PDF Reports|
|  - Firebase App Check            |  |  Security Rules,    |  | - Encrypted  |
|  - Cloud Functions (Blaze/Emu)*  |  |  Composite Indexes) |  |   Log Arch.  |
+------------------+---------------+  +----------+----------+  +------+-------+
                   | Firebase Admin SDK (SA Key, Local/Server Only)   |
                   v                             ^                    ^
+------------------------------------------------+--------------------+-------+
|              LOCAL PYTHON / DOCKER COMPUTE TIER (Zero Cloud VM Cost)        |
|                                                                             |
|  +---------------------------------+    +--------------------------------+  |
|  | FastAPI Security & ML Gateway   |    | Flower FL Coordinator (Local)  |  |
|  | (:8000, TLS/HTTPS optional)     |    | (:8080 TLS gRPC + Metrics)     |  |
|  | - Firebase ID Token Verifier    |    | - Krum / TrimmedMean / FedAvg  |  |
|  | - Zero-Trust RBAC & Rate Limit  |    | - Z-Score Malicious Detection  |  |
|  | - AES-256-GCM + HKDF Key Vault  |    | - Pairwise Secure Aggregation  |  |
|  | - ML Inference (LSTM/RF/XGBoost)|    | - Validated RDP Privacy Acct.  |  |
|  | - SHAP Explainable AI Engine    |    +---------------+----------------+  |
|  | - Automated Response Coordinator|                    | TLS + Client Auth |
|  | - Local Fallback for Functions* |       +------------+------------+      |
|  | - Prometheus /metrics           |       v            v            v      |
|  +---------------------------------+   [Client A]  [Client B] ... [Client N]|
|                                        (>=5 configurable local tenant nodes)|
|  +---------------------------------+   Raw telemetry NEVER leaves client!   |
|  | Prometheus (:9090) & Grafana    |                                        |
|  | (:3001) via Docker Compose      |                                        |
|  +---------------------------------+                                        |
+-----------------------------------------------------------------------------+
```

> **Honesty & Deployment Transparency:** The Flower FL Coordinator and Python FastAPI ML service run **locally** (via Python or Docker Compose) during initial development and demonstration. They are **not** publicly cloud-hosted inside Firebase Cloud Functions.

---

## 2. Firebase Plan & Cost Analysis (Spark vs. Blaze)

Per official Firebase pricing documentation verified prior to architecture lock:

| Service | Spark Plan (No-Cost) Quota | Blaze Required? | Architecture Decision |
|---|---|---|---|
| **Firebase Authentication** | 50,000 MAUs (Email/Password, Password Reset, Custom Claims, ID Tokens). Phone/SMS MFA requires Blaze. | **No** (Email/Pass & Claims) | Use Email/Password + Custom Claims + server ID token verification. Avoid SMS MFA. |
| **Cloud Firestore** | 1 GiB storage, 50k reads/day, 20k writes/day, 20k deletes/day, 10 GiB/mo egress. | **No** | Primary cloud DB. Enforce pagination, query limits, batching, and avoid high-frequency heartbeat writes. |
| **Firebase Hosting** | 10 GiB storage, 360 MB/day transfer, free SSL/HTTPS, SPA rewrites. | **No** | Primary frontend host for production dashboard build. |
| **Firebase App Check** | Free verification with reCAPTCHA v3 (within standard reCAPTCHA free quota). | **No** | Enable on Web App + Firestore/Auth/Storage where supported; support debug token for local dev. |
| **Firebase Local Emulator Suite** | Auth, Firestore, Storage, Functions, Hosting emulators locally. | **No** | Primary zero-cost local testbed for Security Rules, Functions, and CI integration tests. |
| **Cloud Functions for Firebase** | **Unavailable for live deployment on Spark** (requires Cloud Billing / Blaze account due to Cloud Build/Run backing; includes 2M invocations/mo free tier once on Blaze). | **Yes (for live cloud deploy)** | Implement `functions/` cleanly for Emulator + optional Blaze deploy, AND mirror lightweight alert/audit/validation triggers in local FastAPI service so **100% of features work on Spark without billing**. |
| **Firebase Storage** | Legacy projects retain 5 GB / 1 GB/day egress; **newly provisioned default buckets generally require Blaze** (with 5 GB `us-central1`/`us-west1`/`us-east1` no-cost tier). | **Potentially Yes** | Implement `storage.rules` + client/Admin uploads (PDF reports, encrypted archives, model metadata). Provide automatic **local encrypted artifact fallback** (`artifacts/` served securely via authorized FastAPI endpoint) if Storage bucket isn't provisioned on Spark. |

---

## 3. Firestore Data Model (11 Core Collections)

To satisfy both tenant isolation and efficient querying, we combine top-level governance/registry collections with **tenant-scoped subcollections or strict `tenantId`-indexed collections**:

| Collection | Path Pattern | Purpose & Key Fields | Access Policy |
|---|---|---|---|
| `users` | `users/{uid}` | Profile synced with Firebase Auth (`uid`, `email`, `displayName`, `role`, `tenantId`, `isActive`, `isVerified`, `createdAt`, `verifiedBy`, `verifiedAt`) | Self-read (`uid == auth.uid`); admin read/write; no self-elevation of `role`/`tenantId`/`isVerified`. |
| `tenants` | `tenants/{tenantId}` | Tenant registry (`name`, `slug`, `isActive`, `keyVersion`, `keyFingerprint`, `encryptionAlgo`, `createdAt`) — **never stores raw AES keys** | Admin create/update; active tenant members can read own tenant metadata. |
| `tenant_members` | `tenants/{tenantId}/members/{uid}` (and lookup index `tenant_members/{uid}_{tenantId}`) | Authoritative user-to-tenant RBAC mapping (`uid`, `tenantId`, `role`: `admin\|analyst\|user`, `status`: `pending\|active\|restricted`, `assignedAt`) | Admin/server write only; tenant users read own membership. |
| `threat_events` | `tenants/{tenantId}/threat_events/{eventId}` | Raw/scored ML threat metadata (`tenantId`, `eventType`, `threatLabel`, `severity`, `anomalyScore`, `confidence`, `mlModel`, `shapExplanation`, `recommendedAction`, `sourceIp`, `timestamp`, `status`) | Strictly scoped to `tenantId` (`isTenantMember(tenantId)`); admins/server only write. |
| `security_alerts` | `tenants/{tenantId}/security_alerts/{alertId}` | Actionable alerts escalated from `threat_events` or CI/CD gates (`tenantId`, `threatEventId`, `severity`, `status`: `open\|acknowledged\|resolved`, `requiresApproval`, `acknowledgedBy`, `timestamp`) | Tenant members/analysts read own tenant; analysts/admins update status via validated transitions. |
| `audit_logs` | `tenants/{tenantId}/audit_logs/{logId}` | Append-only immutable audit records (`tenantId`, `actorUid`, `eventType`, `severity`, `sourceIp`, `details`, `integrityHash`, `timestamp`) | Tenant-scoped read; **create-only by trusted backend/Functions** (client update/delete denied). |
| `response_history` | `tenants/{tenantId}/response_history/{respId}` | Automated/approved security responses (`alertId`, `actionType`: `block_request\|revoke_session\|restrict_account\|notify_admin`, `approvalStatus`: `pending\|approved\|rejected\|executed`, `approvedBy`, `timestamp`) | Tenant analyst/admin read; high-impact actions require explicit admin approval record. |
| `federated_rounds` | `federated_rounds/{roundId}` | FL coordinator round metadata (`roundNum`, `strategy`, `modelVersion`, `participatingClients`, `rejectedClients`, `accuracy`, `loss`, `durationMs`, `timestamp`) — **no raw tenant datasets** | Authenticated read; trusted FL coordinator / Admin SDK write only. |
| `model_metrics` | `model_metrics/{metricId}` | Comparative ML evaluation (`modelName`: `LSTM\|RandomForest\|XGBoost\|Autoencoder`, `scope`: `local\|federated`, `accuracy`, `precision`, `recall`, `f1`, `fpr`, `confusionMatrix`, `latencyMs`, `evaluatedAt`) | Authenticated read; trusted ML backend write only. |
| `privacy_metrics` | `privacy_metrics/{roundId}` | Differential privacy accounting (`roundNum`, `accountantType`: `RDP\|Moments`, `noiseMultiplier`, `clipNorm`, `roundEpsilon`, `cumulativeEpsilon`, `delta`, `budgetLimit`, `budgetExceeded`, `timestamp`) | Authenticated read; trusted FL coordinator write only. |
| `system_settings` | `system_settings/{settingId}` | Global platform config (`dpMaxEpsilon`, `flStrategy`, `krumF`, `rateLimits`, `appCheckEnforced`, `updatedBy`, `updatedAt`) | Admin read/write; non-sensitive subset readable by authenticated users. |

---

## 4. Trust Boundaries & Token Verification Flow

1. **Never Trust Frontend Tenant Identity**: Frontend never asserts `tenant_id` or `role` authoritatively.
2. **Firebase ID Token Verification**:
   - Browser signs in via Firebase Auth (`signInWithEmailAndPassword`).
   - API calls include `Authorization: Bearer <Firebase_ID_Token>` (plus `X-Firebase-AppCheck` header when App Check is active).
   - FastAPI verifies the token using `firebase_admin.auth.verify_id_token(token, check_revoked=True)`.
   - FastAPI derives `role` and `tenant_id` from **verified Firebase Custom Claims** cross-checked against Firestore `users/{uid}` and `tenants/{tenantId}/members/{uid}` (`isVerified == true`, `isActive == true`).
3. **Local Python FL / ML Service ↔ Firebase Auth**:
   - Local FastAPI & Flower FL Coordinator authenticate to Firebase using a local `GOOGLE_APPLICATION_CREDENTIALS` service account JSON stored **exclusively on the server filesystem** (excluded via `.gitignore`, never imported or bundled in `frontend/`).
   - During local emulator testing, services use `FIREBASE_AUTH_EMULATOR_HOST`, `FIRESTORE_EMULATOR_HOST`, and `FIREBASE_STORAGE_EMULATOR_HOST` with zero cloud credentials required.

---

## 5. Firebase Storage Layout & Security

```
gs://<project-bucket>/
└── tenants/
    └── {tenantId}/
        ├── reports/        # Exported PDF / CSV security reports (max 10 MB, application/pdf or text/csv)
        └── archives/       # AES-256-GCM encrypted log archives ONLY (max 25 MB, application/octet-stream)
└── models/
    └── global/             # Global FL model checkpoints/metadata (Admin SDK write only; no tenant raw data)
```
- `storage.rules` strictly enforces `request.auth != null`, tenant membership (`request.auth.token.tenant_id == tenantId`), `contentType` allowlists, and `request.resource.size` caps.
- Private encryption keys and unencrypted raw tenant CSVs are **never** uploaded to Firebase Storage or exposed via public download URLs.

---

## 6. Future Cloud Compute Migration Path (When Funding Is Available)

When Google Cloud billing / compute budget becomes available:
1. **FastAPI + ML Inference Gateway** → Containerize and deploy to **Google Cloud Run** (`--min-instances=0` or `1`, HTTPS managed automatically, Workload Identity for Firestore/Storage without static JSON keys).
2. **Flower FL Coordinator** → Deploy to **Cloud Run (with HTTP/2 gRPC & CPU/GPU allocation)** or **GKE Autopilot / Compute Engine VM** with Cloud Load Balancing TLS termination, while tenant FL clients continue running inside each tenant's own isolated cloud VPC/cluster.
3. **Cloud Functions v2** → Activate live deployment on Blaze plan for event-driven Firestore triggers (`onDocumentCreated` on `security_alerts` and `audit_logs`) and scheduled budget/cleanup jobs.
4. **Secret Manager** → Migrate local `TENANT_MASTER_KEY` and service account credentials into **Google Cloud Secret Manager** with automatic key rotation.
