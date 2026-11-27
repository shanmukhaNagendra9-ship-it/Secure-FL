# API Documentation — SecureFL Gateway v3.0.0

Base URL (local): `http://127.0.0.1:8000` | Interactive OpenAPI Docs: `/docs`

All protected routes require `Authorization: Bearer <Firebase_ID_Token_or_Local_JWT>` (and `X-Firebase-AppCheck` when `FIREBASE_APP_CHECK_ENFORCED=true`).

## Authentication (`/api/v1/auth`)
- `POST /api/v1/auth/register` — Register `user` or `analyst` (`admin` forbidden) in pending verification state.
- `POST /api/v1/auth/login` — Authenticate verified, active, unrestricted accounts; records brute-force failures (>=5 triggers pending account restriction).
- `POST /api/v1/auth/firebase-sync` — Verify Firebase Auth ID token (`verify_id_token(..., check_revoked=True)`) and sync tenant membership & custom claims.
- `POST /api/v1/auth/password-reset` — Trigger password reset workflow without user enumeration.
- `POST /api/v1/auth/logout` — Revoke local JWT `jti` and Firebase refresh tokens.
- `GET /api/v1/auth/public-tenants` — List active tenant organization IDs/names for onboarding.
- `GET /api/v1/auth/me` — Current authenticated user profile.

## Admin Governance (`/api/v1/admin`) *(Admin only)*
- `GET /api/v1/admin/users`, `GET /api/v1/admin/pending-users`
- `POST /api/v1/admin/users/create`
- `POST /api/v1/admin/users/{user_id}/verify` — Approve or reject pending registration + sync Firebase custom claims.
- `POST /api/v1/admin/users/{user_id}/update-role`, `/change-tenant`, `/toggle-active`, `/unrestrict`, `/revoke-sessions`
- `GET /api/v1/admin/overview`

## Tenant Isolation & AES-256-GCM Vault (`/api/v1/tenants`)
- `GET /api/v1/tenants/me/current` — Current tenant metadata + non-reversible HKDF `key_fingerprint` (raw keys never exposed).
- `POST /api/v1/tenants/me/rotate-key` — Increment tenant HKDF key version.
- `POST /api/v1/tenants/me/encrypt-archive`, `GET /api/v1/tenants/me/archives`, `GET /api/v1/tenants/me/archives/{archive_name}`
- `GET /api/v1/tenants/`, `POST /api/v1/tenants/`, `GET /api/v1/tenants/{tenant_id}`, `GET /api/v1/tenants/{tenant_id}/stats`, `DELETE /api/v1/tenants/{tenant_id}`

## Threats, ML Inference & XAI (`/api/v1/threats`)
- `GET /api/v1/threats/` — Paginated tenant-scoped (or admin global) threat alerts.
- `GET /api/v1/threats/summary` — Aggregate severity & threat-type breakdown.
- `GET /api/v1/threats/realtime` — Authenticated Bearer SSE stream (`401` if unauthenticated, `403` on non-admin cross-tenant override).
- `POST /api/v1/threats/analyze` — Real ML inference (`lstm`, `random_forest`, `xgboost` + `AutoencoderDetector`) + XAI explanation + automated response escalation.
- `GET /api/v1/threats/{alert_id}/explain` — Feature attributions & recommended action.
- `POST /api/v1/threats/{alert_id}/acknowledge`, `POST /api/v1/threats/{alert_id}/resolve`
- `POST /api/v1/threats/simulate` — Inject labeled synthetic telemetry event through real ML + XAI pipeline.

## Security Response Center (`/api/v1/responses`)
- `GET /api/v1/responses/` — Automated & pending responses (`response_history`).
- `POST /api/v1/responses/trigger` — Queue manual response (subject to admin approval for high-impact actions).
- `POST /api/v1/responses/{response_id}/decide` — Admin approve/reject gate executing `restrict_account` / `revoke_session`.

## Federated Learning, Privacy & Benchmarks (`/api/v1/fl`)
- `GET /api/v1/fl/status`, `GET /api/v1/fl/rounds`, `GET /api/v1/fl/model/accuracy`, `GET /api/v1/fl/clients`
- `POST /api/v1/fl/trigger` — Execute genuine 5-client Flower PyTorch FL round(s) with `krum` / `trimmed_mean` / `fedavg` + RDP DP + optional Byzantine poisoning test.
- `GET /api/v1/fl/privacy/budget`, `GET /api/v1/fl/privacy/history`
- `GET /api/v1/fl/benchmarks`, `POST /api/v1/fl/benchmarks/run` — Comparative LSTM vs. Random Forest vs. XGBoost evaluation.

## Audit, DevSecOps & System (`/api/v1/audit`, `/api/v1/cicd`, `/api/v1/firebase`, `/api/v1/settings`)
- `GET /api/v1/audit/logs`, `GET /api/v1/audit/summary`, `GET /api/v1/audit/logs/export` (CSV), `GET /api/v1/audit/reports/pdf` (PDF), `POST /api/v1/audit/logs`
- `POST /api/v1/cicd/scan`, `GET /api/v1/cicd/history`, `GET /api/v1/cicd/status`
- `GET /api/v1/firebase/status`, `GET /api/v1/firebase/client-config`, `GET /api/v1/settings`, `PUT /api/v1/settings`, `GET /metrics`, `GET /health`
