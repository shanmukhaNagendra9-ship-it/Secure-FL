# Testing & Security Verification Report — SecureFL v3.0.0

**Execution Environment:** Windows 11, Python 3.11.9 (`C:\Users\shanm\Python311\python.exe`), isolated temporary SQLite databases per test fixture (`tests/conftest.py`).  
**Date:** 2026-11-26

---

## 1. Automated Test Suite Results (`pytest`)

- **Command:** `pytest tests/ --cov=backend --cov=federated_learning --cov-report=term-missing -v --tb=short`
- **Outcome:** **34 passed, 0 failed** in `53.27s`
- **Total Line Coverage:** **86%** (3,718 statements, 518 missed — passes the 80% CI/CD coverage gate)

### Per-Module Coverage Breakdown
| Module | Statements | Missed | Coverage |
|---|---|---|---|
| `backend/metrics.py` | 14 | 0 | **100%** |
| `backend/schemas.py` | 167 | 1 | **99%** |
| `federated_learning/ml_benchmark.py` | 172 | 5 | **97%** |
| `federated_learning/model.py` | 169 | 5 | **97%** |
| `backend/database.py` | 172 | 7 | **96%** |
| `backend/response_engine.py` | 58 | 3 | **95%** |
| `backend/middleware.py` | 86 | 5 | **94%** |
| `federated_learning/pipeline_security.py` | 63 | 4 | **94%** |
| `federated_learning/data_simulator.py` | 100 | 7 | **93%** |
| `backend/routers/responses.py` | 61 | 5 | **92%** |
| `backend/routers/tenants.py` | 123 | 10 | **92%** |
| `backend/routers/audit.py` | 117 | 12 | **90%** |
| `backend/routers/cicd.py` | 79 | 8 | **90%** |
| `backend/routers/system.py` | 41 | 4 | **90%** |
| `federated_learning/privacy.py` | 205 | 21 | **90%** |
| `federated_learning/explainability.py` | 61 | 7 | **89%** |
| `federated_learning/fl_runner.py` | 98 | 12 | **88%** |
| `backend/isolation.py` | 171 | 22 | **87%** |
| `backend/routers/admin.py` | 187 | 24 | **87%** |
| `backend/config.py` | 97 | 14 | **86%** |
| `backend/main.py` | 266 | 46 | **83%** |
| `federated_learning/client.py` | 149 | 26 | **83%** |
| `backend/repositories.py` | 112 | 20 | **82%** |
| `backend/storage_service.py` | 75 | 16 | **79%** |
| `backend/routers/threats.py` | 237 | 57 | **76%** |
| `federated_learning/aggregation.py` | 125 | 30 | **76%** |
| `federated_learning/server.py` | 127 | 30 | **76%** |
| `backend/routers/federated.py` | 133 | 33 | **75%** |
| `backend/auth.py` | 126 | 42 | **67%** |
| `backend/firebase_client.py` | 127 | 42 | **67%** |

---

## 2. Security, SAST, Dependency & Lint Gates

| Check | Tool & Command | Result |
|---|---|---|
| **SAST** | `bandit -r backend federated_learning scripts -ll -ii` | **PASS** — 0 Medium, 0 High issues across 6,789 lines scanned |
| **Secret Scan** | `detect_secrets scan --all-files backend federated_learning scripts frontend/js` | **PASS** — `"results": {}` (0 exposed secrets) |
| **Linting** | `flake8 backend federated_learning tests --max-line-length=135 --count` | **PASS** — 0 errors |
| **Dependency Audit** | `pip_audit` (after replacing `python-jose`/`ecdsa` with `PyJWT[crypto]` and upgrading `certifi`, `opentelemetry-api`, `setuptools`) | **0 vulnerabilities in application dependencies** *(host installer tools `pip 24.0`/`uv 0.12.24` ignored; `torch 2.15.0+cpu` skipped as non-PyPI wheel)* |

---

## 3. Functional & Security Verification Matrix

- **`[SEC-01]` Privilege Escalation Blocked (`tests/test_api.py`)**: Self-registration as `admin` returns `422`; unverified accounts cannot log in (`403`) until admin approval (`200`).
- **`[SEC-02]` SSE Stream Auth & Isolation (`tests/test_api.py`)**: Unauthenticated or invalid-token requests to `/api/v1/threats/realtime` return `401`; non-admin `?tenant_id` override returns `403`.
- **Cross-Tenant & Cryptographic Isolation (`tests/test_isolation.py`, `tests/test_api.py`)**: Salted HKDF key derivation, AES-256-GCM AAD rejection on foreign tenant key/AAD, fail-closed `@enforce_tenant_isolation` (`401`/`403`), `DataLeakageDetector`, and encrypted storage archive isolation all verified.
- **Session Revocation & Brute-Force Approval Gate (`tests/test_api.py`, `tests/test_ml_xai_responses.py`)**: `/api/v1/auth/logout` revokes JWT `jti` (`401` on reuse); 5 failed logins trigger a `pending` `restrict_account` entry that does NOT auto-lock the account until explicit admin approval (`POST /api/v1/responses/{id}/decide`).
- **Firebase Cloud / Emulator Mocks (`tests/test_coverage_extended.py`)**: `FirebaseService` emulator initialization, `verify_id_token`, `set_custom_claims`, `revoke_refresh_tokens`, `/api/v1/auth/firebase-sync`, and `FirestoreSyncRepository` verified with mocked SDK clients.
- **Not Executed Locally (Tooling Absent)**: `tests/firebase_rules.test.mjs` and Docker Compose container builds were not run locally because `node`, `firebase`, and `docker` are not installed on this machine's `PATH`.
