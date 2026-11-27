# Project Analysis — Multi-Tenant Cloud Data Isolation & Federated Learning Platform

**Analysis Date:** 2026-11-25  
**Scope:** Full static and runtime read-only inspection of `c:\Users\shanm\OneDrive\Desktop\multi` prior to any code modifications (Phase 1).  
**Target Upgrade:** Firebase-backed managed cloud architecture (Spark-first, local Python/Docker for compute-intensive ML & Flower FL).

---

## 1. Executive Summary

The existing project implements a solid foundational prototype for multi-tenant DevSecOps threat detection with:
- A **FastAPI + SQLAlchemy (async)** REST & SSE backend (`backend/`) using local SQLite (`multitenant.db`) by default.
- A **single-file vanilla HTML/CSS/JS dark-mode dashboard** (`frontend/index.html`) supporting login, registration with pending admin approval, threat simulation, audit logs, and CI/CD gate simulation.
- **Cryptographic isolation primitives** (`backend/isolation.py`) with AES-256-GCM, HKDF-SHA256 key derivation, `contextvars`, and payload leakage scanning.
- **Federated Learning modules** (`federated_learning/`) defining an LSTM & Autoencoder (`model.py`), DP mechanisms (`privacy.py`), Byzantine-robust aggregators (`aggregation.py`), non-IID data simulator (`data_simulator.py`), and DevSecOps scanner (`pipeline_security.py`).
- **Infrastructure & CI/CD templates** (`docker-compose.yml`, `k8s/`, `monitoring/`, `.github/workflows/devsecops-pipeline.yml`).

However, runtime inspection revealed **major integration gaps, broken ML/FL execution paths, missing dependencies (`torch`, `pytest`, Node/Firebase CLI), mock-stubbed tests, synthetic/hardcoded FL dashboard metrics, and critical security vulnerabilities** (detailed in [SECURITY_AUDIT.md](SECURITY_AUDIT.md)).

---

## 2. Repository & File Inventory

### 2.1 Existing Files Verified on Disk
| Area | Files Observed | Notes |
|---|---|---|
| **Root** | `.env.example`, `.gitignore`, `docker-compose.yml`, `multitenant.db` (126,976 B), `README.md`, `REPORT.md`, `SLIDES_OUTLINE.md`, `requirements.txt`, `run_all.bat`, `run_simulation.bat`, `start_backend.bat`, `start_dashboard.bat`, `start_full_stack.bat` | `.env` does not exist; `multitenant.db` has live test/demo records from prior runs. |
| **Backend** | `backend/main.py` (636 lines), `backend/auth.py` (211), `backend/database.py` (290), `backend/isolation.py` (340), `backend/schemas.py` (183), `backend/Dockerfile` (80) | Routers in `backend/routers/`: `admin.py` (388), `audit.py` (166), `cicd.py` (137), `federated.py` (215), `tenants.py` (210), `threats.py` (402). |
| **Federated Learning** | `federated_learning/__init__.py`, `model.py` (488), `client.py` (263), `server.py` (296), `aggregation.py` (449), `privacy.py` (471), `data_simulator.py` (243), `pipeline_security.py` (177), `Dockerfile` (77) | PyTorch models & Flower client/server cannot currently run in local Python 3.11 because `torch` is not installed and there are constructor/property bugs. |
| **Frontend** | `frontend/index.html` (2,467 lines), `frontend/Dockerfile` (42), `frontend/nginx.conf` (55) | Monolithic vanilla JS SPA (no React/Vite build, no Firebase Web SDK). |
| **Data & Metrics** | `data/tenant_a/logs.csv`, `data/tenant_b/logs.csv`, `data/tenant_c/logs.csv` (3,000 rows each + header), `metrics/fl_metrics.json` (151 lines) | `fl_metrics.json` contains 5 baseline rounds + 6 trigger-incremented rounds (capped at `0.985` accuracy). |
| **Monitoring & K8s** | `monitoring/prometheus.yml`, `monitoring/alert_rules.yml`, `k8s/{namespace,network-policy,api-gateway-deployment,fl-server-deployment,tenant-clients-deployment}.yml` | Referenced Grafana JSONs, Vault configs, and `backend/db/init.sql` do not exist. |
| **CI/CD & Scripts** | `.github/workflows/devsecops-pipeline.yml` (762 lines), `scripts/{run_simulation.py,setup.ps1,setup.sh}` | CI workflow passes errors via `|| true` and tests non-existent `/api/v1/auth/token` and `/api/v1/tenants/{id}/data` endpoints. |
| **Tests** | `tests/{test_api.py,test_federated_learning.py,test_isolation.py,test_pipeline_security.py,test_real_monitoring.py}` | `test_federated_learning.py` and `test_isolation.py` test inline stub classes instead of project source files. |

### 2.2 Documentation vs. Reality Discrepancies
`README.md` describes directories and files that **do not exist** in the repository (`requirements-dev.txt`, `data_isolation/`, `backend/models/`, `backend/middleware/`, `backend/routes/`, `kubernetes/`, `docs/`, `models/`, `tests/conftest.py`, `tests/test_fl_server.py`, etc.).

---

## 3. Existing Backend, Database & API Analysis

### 3.1 Database Configuration & Observed State
- **ORM / Engine (`backend/database.py`)**: SQLAlchemy 2.0 async engine defaulting to `sqlite+aiosqlite:///./multitenant.db` (configurable via `DATABASE_URL` to PostgreSQL `asyncpg`).
- **Tables Defined**:
  1. `tenants` (`id`, `name`, `created_at`, `encryption_key`, `is_active`) — **5 rows** in `multitenant.db`: 3 seeded tenants (`Tenant Alpha (E-Commerce)`, `Tenant Beta (Financial Services)`, `Tenant Gamma (Cloud Core & CI/CD)`) plus 2 test tenants (`health`, `home1`).
  2. `users` (`id`, `username`, `hashed_password`, `tenant_id`, `role`, `is_active`, `is_verified`, `email`, `full_name`, `created_at`, `verified_by`, `verified_at`) — **10 rows** in `multitenant.db` (all 10 currently `is_verified=1`, including `pending_analyst`, `new_candidate`, `candidate_sec_eng`).
  3. `threat_alerts` (`id`, `tenant_id`, `threat_type`, `confidence`, `timestamp`, `source_ip`, `destination_ip`, `description`, `status`, `acknowledged_by`, `acknowledged_at`) — **29 rows** (`13 open`, `16 resolved`).
  4. `audit_logs` (`id`, `tenant_id`, `event_type`, `severity`, `timestamp`, `details`, `source_ip`) — **55 rows**.
  5. `fl_rounds` (`id`, `round_num`, `accuracy`, `loss`, `privacy_epsilon`, `privacy_delta`, `timestamp`, `participating_tenants`, `model_path`) — **0 rows** (never populated by FL server or API).
- **Missing Collections / Tables Required by Upgrade**:
  - No `tenant_members`, `model_metrics`, `privacy_metrics`, `security_alerts` (separate from or enriched `threat_events`), `response_history`, `system_settings`, or `threat_events` (raw/ML-scored event stream).

### 3.2 Existing Authentication (`backend/auth.py` & `backend/main.py`)
- Custom HS256 JWT tokens via `python-jose` + `bcrypt` password hashing.
- Roles supported: `admin`, `analyst`, `user`.
- Registration flow creates `is_verified=False` users; `/admin/users/{user_id}/verify` approves/rejects them.
- **No Firebase Auth**, no password reset, no email verification, no refresh/revocation (`jti` is created in `create_access_token` but never stored or checked), no Firebase App Check.

### 3.3 Existing API Surface
| Router / File | Prefix | Endpoints | Implementation Status |
|---|---|---|---|
| `main.py` | `/` & `/api/v1` | `POST /auth/register`, `POST /auth/login`, `GET /auth/public-tenants`, `GET /auth/me`, `GET /`, `GET /dashboard`, `GET /api/v1/info`, `GET /health`, `GET /api/v1/stats` | Implemented (local SQLite/JWT). `/api/v1/stats` reads `fl_metrics.json` and hardcodes `tenants_count=1, users_count=1` for non-admins. |
| `admin.py` | `/api/v1/admin` | `GET /users`, `GET /pending-users`, `POST /users/{id}/verify`, `POST /users/{id}/toggle-active`, `POST /users/{id}/update-role`, `POST /users/{id}/change-tenant`, `POST /users/create`, `GET /overview` | Implemented (SQLite). Missing Firebase Auth sync & custom claims update. |
| `tenants.py` | `/api/v1/tenants` | `GET /me/current`, `GET /`, `POST /`, `GET /{id}`, `GET /{id}/stats`, `DELETE /{id}` | Implemented (SQLite). Generates random `encryption_key` stored plaintext in DB (unused by `TenantKeyVault`). |
| `threats.py` | `/api/v1/threats` | `GET /summary`, `GET /realtime` (SSE), `GET /`, `POST /{id}/acknowledge`, `POST /{id}/resolve`, `POST /simulate` | Partially implemented. No real ML inference endpoint; `/simulate` creates random synthetic threats; `/realtime` SSE polls SQLite every 4s and has critical auth/tenant-isolation bypasses. |
| `federated.py` | `/api/v1/fl` | `GET /status`, `GET /rounds`, `GET /model/accuracy`, `GET /privacy/budget`, `GET /clients`, `POST /trigger` | **Mocked/Broken**: `/clients` returns 3 hardcoded dicts (`samples_count=4000`); `/trigger` synthetically increments numbers in `metrics/fl_metrics.json` without running Flower; `fl_rounds` DB table is empty. |
| `audit.py` | `/api/v1/audit` | `GET /logs`, `GET /summary`, `GET /logs/export`, `POST /logs` | Implemented. Browser CSV export broken (`index.html` sends `?token=` query param while backend requires `Authorization: Bearer` header). |
| `cicd.py` | `/api/v1/cicd` | `POST /scan`, `GET /status` | `/scan` evaluates numeric thresholds (`secrets_detected`, `vulnerabilities_detected`, `files_changed`); `/status` returns static hardcoded strings. |

---

## 4. Existing Frontend Analysis (`frontend/index.html`)

- **Architecture**: Single 2,467-line HTML file containing inline CSS, SVG generators, and vanilla JavaScript. Served by FastAPI (`/` and `/dashboard`) or Nginx (`frontend/Dockerfile`).
- **UI Design**: GitHub-dark palette (`#0d1117`, `#161b22`), basic cards/tables, custom inline SVGs for Donut chart, FL Accuracy Trend, and DP Epsilon Gauge. No light/dark theme toggle, no glassmorphism/violet-blue gradient styling, no React build.
- **Implemented Pages**:
  - Admin tabs: System Overview, Admin Verification & Users, Real Tenants, Threat Center, FL Model Monitor, Audit Logs, CI/CD Security Gate.
  - Non-admin tabs: Tenant Security Hub (`page-user-hub`), My Tenant Threats, My Audit Trail.
- **Missing / Fake Features in Frontend**:
  - `testIsolationProbe()` (lines 2427–2443) uses `setTimeout` and displays a fake `HTTP 403 Forbidden` success toast without making any backend request.
  - Missing modules required for target upgrade: Attack History, Model Performance Comparison (LSTM vs. Random Forest vs. XGBoost + confusion matrix + detection latency), Privacy Monitoring (per-round accounting & parameters), Explainable AI (SHAP/attributions + recommended actions), Security Response Center (approvals, session revocation, restrictions), User & Role Management (Firebase Auth + password reset), Firebase Backend Status, DevSecOps Status (real CI/CD results), Downloadable Reports (PDF via Firebase Storage / local fallback).
  - Pre-fills `admin` / `admin123` and exposes quick-credential chips on the login modal.

---

## 5. Federated Learning, ML & Privacy Implementation Audit

### 5.1 Critical Runtime Defects in `federated_learning/`
1. **Incompatible `PrivacyAccountant` API calls**:
   - `federated_learning/privacy.py` defines `PrivacyAccountant.__init__(self, total_epsilon=10.0, total_delta=1e-5)` and property `spent_epsilon`.
   - `federated_learning/client.py` (lines 130, 187, 191, 197) and `federated_learning/server.py` (lines 70, 165) pass `total_budget=10.0` (`TypeError`) and read `self.accountant.epsilon_spent` (`AttributeError`).
2. **Incompatible `RobustAggregator` API calls**:
   - `federated_learning/aggregation.py` defines `RobustAggregator.__init__(krum_f=1, trim_beta=0.1, malicious_threshold=3.0, auto_detect=True)` and `aggregate(..., strategy="fedavg")`.
   - `federated_learning/server.py` line 68 passes `strategy=strategy_name` to `RobustAggregator()` (`TypeError`) and line 124 omits `strategy=self.strategy_name` in `aggregate()`.
3. **Broken Differential Privacy Pipeline**:
   - `client.py` instantiates `self.privacy_mech = GaussianMechanism()` (line 129) and clips gradients during local Adam steps (line 168), **but never adds Gaussian noise** to transmitted updates; it still calls `accountant.spend(epsilon=0.2)`!
   - `server.py` adds Gaussian noise to *aggregated* parameters using `epsilon=self.privacy_epsilon` (default `2.0`), then calls `accountant.spend(epsilon=0.15)` — **disconnecting accounting from noise magnitude**.
   - `PrivacyAccountant` only performs naive linear summation (`spent_epsilon += epsilon`) rather than validated Rényi DP (RDP) / Moments Accountant / PRV composition across subsampled batches/rounds.
4. **Krum Client Count Constraint**:
   - Krum requires $n \ge 2f + 3$ ($n > 2f + 2$). With only 3 tenant clients (`tenant_a`, `tenant_b`, `tenant_c`), `krum(weights_list, f=1)` always raises `ValueError` (`n=3` requires $n \ge 5$).
5. **Input Dimension & Autoencoder Mismatch**:
   - `model.py` sets `LSTMThreatDetector.INPUT_SIZE = 20` and `AutoencoderDetector.INPUT_SIZE = 20`, whereas `data_simulator.py` and `pipeline_security.py` define **19** `FEATURE_COLUMNS`.
   - `AutoencoderDetector` decoder ends with `nn.Sigmoid()` (bounded `[0, 1]`), incompatible with `StandardScaler`-transformed features.
6. **Simulation Script vs. Real FL (`scripts/run_simulation.py`)**:
   - Uses scikit-learn `RandomForestClassifier` trained independently on each tenant, then averages `predict_proba` outputs with ad-hoc `N(0, 0.012)` noise. It does **not** run Flower, PyTorch LSTM, XGBoost, Krum, or validated DP accounting.
7. **Simulated Secure Aggregation (`privacy.py` lines 291–432)**:
   - `SecureAggregator` uses a single hardcoded shared seed (`42`) known to both client and server and is not integrated into Flower transport (plus Flower gRPC runs plaintext without TLS).
8. **Missing Capabilities**:
   - No **XGBoost** model or LSTM vs. RF vs. XGBoost benchmark persistence.
   - No **Explainable AI** (SHAP / feature attribution).
   - No real-time log ingestion / inference pipeline connecting ML models to `ThreatAlert` / `threat_events`.

---

## 6. Dependency, Toolchain & Test Inspection

### 6.1 Local Environment Findings (Windows Host)
- **Python 3.11.9 (`C:\Users\shanm\Python311\python.exe`)**: Active runtime referenced by `.bat` launchers. Installed packages include `fastapi 0.138.2`, `starlette 1.3.1`, `pydantic 2.14.1`, `SQLAlchemy 2.1.4`, `flwr 1.40.0`, `scikit-learn 1.9.1`, `pandas 3.0.6`, `numpy 2.4.6`, `cryptography 50.0.2`, `bcrypt 5.0.0`, `passlib 1.7.4`, `python-jose 3.5.0`, `httpx 0.28.1`, `uvicorn 0.49.0`.
- **Missing Python Packages in Python 3.11**: `torch`, `torchvision`, `pytest`, `pytest-asyncio`, `pytest-cov`, `bandit`, `safety`, `semgrep`, `pip-audit`, `detect-secrets`, `prometheus-client`, `asyncpg`, `pydantic-settings`, `python-multipart`, `aiofiles`, `xgboost`, `shap`, `opacus`, `firebase-admin`.
- **Python 3.12 (`C:\Users\shanm\AppData\Local\Python\pythoncore-3.12-64\python.exe`)**: Empty environment (`pip 25.0.1` only).
- **Missing CLI Tools on `PATH`**: `node`, `npm`, `npx`, `firebase`, `docker`, `git`, `gcloud` were all `NOT FOUND`.
- **Dependency Conflicts & Version Risks**:
  - `requirements.txt` pins `flwr==1.7.0`, whereas Python 3.11 has `flwr 1.40.0` installed (though `fl.server.start_server` and `fl.client.start_numpy_client` remain present in `1.40.0`, they are legacy APIs subject to deprecation warnings/changes).
  - `passlib 1.7.4` is incompatible with `bcrypt 5.0.0` (if passlib's bcrypt handler is ever invoked, it fails on missing `bcrypt.__about__`; `backend/auth.py` currently bypasses `passlib` and calls `bcrypt` directly, making `passlib` dead weight in `requirements.txt`).
  - `numpy 2.4.6` and `pandas 3.0.6` require `torch>=2.3+` and recent `scikit-learn` / `shap` / `xgboost` wheels to avoid ABI incompatibilities.
  - `backend/Dockerfile` and `federated_learning/Dockerfile` fail to build with their `docker-compose.yml` contexts (`./backend` and `./federated_learning`) because `COPY requirements.txt .` looks inside the subdirectory instead of repo root, and `uvicorn main:app` breaks relative imports (`from .auth import ...`).

### 6.2 Observed Import & Test Execution Results (Non-Mutating Against Temp DB Copy)
- **Module Imports**:
  - `backend.main`, `backend.auth`, `backend.database`, `backend.isolation`, `federated_learning.data_simulator`, `federated_learning.pipeline_security` → **OK**.
  - `federated_learning.{model,aggregation,privacy,client,server}` → **FAIL** (`ModuleNotFoundError: No module named 'torch'`).
- **API & Integration Checks (`tests/test_real_monitoring.py` against temp DB copy)**:
  - Root `/`, `/dashboard`, `/api/v1/auth/public-tenants`, admin login, `alpha_user` login, `/api/v1/tenants/me/current` → **200 OK**.
  - `pending_analyst` login returned **200 OK** instead of expected **403** (`AssertionError` at line 68) because `multitenant.db` already has `is_verified=1` for `pending_analyst`.
- **API Tests (`tests/test_api.py` checks via `TestClient` against fresh temp DB)**:
  - `test_health_check` and unauthenticated `401` check → **PASS**.
  - `test_root_endpoint` → **FAIL** (`JSONDecodeError` because `/` returns `frontend/index.html`, whereas JSON is on `/api/v1/info`).
  - All 5 authenticated `test_api.py` tests → **FAIL (401)** because `test_api.py` forges a token for `sub="test_analyst"` which does not exist in the `users` table (`get_current_user` requires an active DB user).
- **Isolation & FL Unit Tests (`tests/test_isolation.py`, `tests/test_federated_learning.py`)**:
  - Both use `try: from isolation... except ImportError:` / `try: from fl... except ImportError:` and therefore **only exercise inline stub classes**, NOT `backend/isolation.py` or `federated_learning/*.py`.
  - Direct verification of `backend/isolation.py` (`TenantKeyVault`, `encrypt_tenant_data`, `decrypt_tenant_data`, `data_leakage_detector`) passed.

---

## 7. Feature Readiness Matrix

| Capability | Current Status | Target Firebase-Backed State |
|---|---|---|
| User Registration & Admin Approval | Partial (SQLite + local JWT; critical admin bypass bug) | Firebase Auth + Firestore `users`/`tenant_members` + server ID token verification + password reset |
| Multi-Tenant Data Isolation | Partial (`isolation.py` unused in routers; ContextVar leak) | Strict Firestore Security Rules + Storage Rules + AES-256-GCM + HKDF + fail-closed server validation |
| Cloud Database & Storage | SQLite (`multitenant.db`) + local disk | Cloud Firestore (11 structured collections, indexes, pagination) + Firebase Storage (or local fallback on Spark) |
| Real-Time Threat Detection | Simulated random alerts + unauthenticated SSE | ML inference pipeline (LSTM/RF/XGBoost) + Firestore real-time listeners + secured SSE |
| Federated Learning (Flower) | Broken (`torch` missing, constructor/attr bugs, `n=3` Krum fails) | Working local Flower coordinator + >=5 configurable tenant clients + model versioning |
| Differential Privacy | Broken (disconnected noise/accounting, linear sum only) | Validated RDP/Opacus/Moments privacy accounting + per-round budget tracking |
| Byzantine Robustness & Secure Agg | Broken constructor; hardcoded seed=42; plaintext gRPC | Validated Krum ($n \ge 2f+3$), Trimmed Mean, Z-score anomaly, TLS + authenticated updates + pairwise-masking protocol |
| Explainable AI | Not implemented | SHAP feature attributions + threat explanation + recommended actions |
| Automated Security Response | Status toggle only (`acknowledge`/`resolve`) | Alerting, session revocation, account restrictions, approval workflow, `response_history` |
| DevSecOps CI/CD | Incomplete (`|| true` bypasses, missing tools) | Hard-failing gates: Bandit, Semgrep, Safety, pip-audit, detect-secrets, Trivy, pytest>=80%, Syft SBOM, Cosign |
| Monitoring & Dashboard | No Prometheus `/metrics`; dark HTML MVP | Prometheus `/metrics` + Grafana + 14-module responsive glassmorphic dashboard on Firebase Hosting |
