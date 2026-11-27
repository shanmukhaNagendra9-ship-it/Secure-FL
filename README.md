# SecureFL — Multi-Tenant Cloud Security, Data Isolation & Federated Learning Platform

**Architecture:** Firebase Managed Cloud Backend (Spark-compatible core + Emulator Suite) paired with Local Python + Docker Compute for PyTorch ML, Flower Federated Learning, Differential Privacy, and Explainable AI.

> **Cost & Infrastructure Transparency:** No dedicated cloud server (EC2/VPS) is required. Firebase Authentication, Cloud Firestore, Firebase Hosting, and Security Rules run on Firebase, while ML training, Flower FL aggregation, and Prometheus/Grafana run locally via Python or Docker Compose. When running without Blaze billing or Firebase credentials, the backend gracefully supports Firebase Emulators or a local SQLite + AES-256-GCM encrypted artifact fallback.

---

## Key Capabilities

- **Firebase Authentication & Zero-Trust RBAC (`backend/auth.py`, `backend/firebase_client.py`)**
  - Email/Password login, password reset, custom claims (`role`, `tenant_id`, `is_verified`), server-side `verify_id_token(..., check_revoked=True)`, session revocation (`revoke_refresh_tokens`), and optional App Check (`X-Firebase-AppCheck`).
  - Public registration strictly prohibits self-registering as `admin`, and **all** accounts require explicit administrator verification before access is granted.
- **Cloud Firestore & Storage Isolation (`firestore.rules`, `storage.rules`, `firestore.indexes.json`)**
  - 11 structured Firestore collections (`users`, `tenants`, `tenant_members`, `threat_events`, `security_alerts`, `audit_logs`, `response_history`, `federated_rounds`, `model_metrics`, `privacy_metrics`, `system_settings`).
  - Tenant-scoped Firebase Storage rules for PDF/CSV reports and AES-256-GCM encrypted `.enc` log archives (with automatic local `artifacts/` fallback).
- **Cryptographic Tenant Isolation (`backend/isolation.py`, `backend/middleware.py`)**
  - Salted **HKDF-SHA256** versioned Data Encryption Key (DEK) derivation (`TenantKeyVault`, zero raw keys stored in DB/Firestore).
  - **AES-256-GCM** encryption binding `associated_data=tenant_id` to prevent cross-tenant tampering.
  - Coroutine-safe `contextvars` with `try/finally` cleanup, fail-closed `@enforce_tenant_isolation`, and recursive `DataLeakageDetector` response middleware.
- **Machine Learning & Explainable AI (`federated_learning/model.py`, `ml_benchmark.py`, `explainability.py`)**
  - Comparative evaluation across **PyTorch LSTMThreatDetector** (19 telemetry features, 5 threat classes), **Random Forest**, and **XGBoost**, plus a linear-output **1D Convolutional Autoencoder** anomaly scorer.
  - **Explainable AI (XAI)** via SHAP `TreeExplainer` and LSTM Gradient × Input attributions returning top risk drivers, anomaly scores, human-readable explanations, and recommended response actions.
- **Flower Federated Learning, RDP Privacy & Byzantine Robustness (`federated_learning/`)**
  - **5+ isolated tenant FL nodes** (`tenant_a`..`tenant_e`) satisfying **Krum ($n > 2f + 2$)** alongside **Coordinate-wise Trimmed Mean**, **FedAvg**, and MAD modified Z-score malicious client detection.
  - Validated **Rényi Differential Privacy (RDP) Moments Accountant** bound directly to client L2 clipping and Gaussian noise multiplier.
  - Optional TLS on Flower gRPC plus **X25519 ECDH Pairwise-Masking Secure Aggregation** (`PairwiseSecureAggregator`).
- **Real-Time Threat Monitoring & Automated Response (`backend/response_engine.py`, `backend/routers/responses.py`)**
  - Authenticated Bearer SSE stream (`GET /api/v1/threats/realtime`) and Firestore `onSnapshot` listeners.
  - Automated brute-force tracking and threat escalation with a mandatory **Admin Approval Gate** before executing high-impact responses (`restrict_account`, `revoke_session`, `block_ip`).
- **14-Module Glassmorphic Cybersecurity Dashboard (`frontend/`)**
  - Zero-build-step responsive dark-navy (`#060b19`) + Light/Dark toggle SPA deployable directly to **Firebase Hosting** or **Nginx**.
- **DevSecOps CI/CD & Observability (`.github/workflows/devsecops-pipeline.yml`, `monitoring/`)**
  - Hard-failing security gates: Bandit, Semgrep, `pip-audit`, Safety, `detect-secrets`, `pytest` coverage gate, Trivy, Syft CycloneDX SBOM, Cosign signing, and Firebase Security Rules tests.
  - Prometheus `/metrics` endpoints on FastAPI (`:8000`) and Flower FL server (`:8081`) + provisioned Grafana dashboard (`:3001`).

---

## Actual Project Structure

```text
multi/
├── .github/workflows/devsecops-pipeline.yml   # Hardened DevSecOps CI/CD gates
├── .env.example                               # Unified environment configuration template
├── .firebaserc                                # Firebase project mapping
├── firebase.json                              # Hosting, Firestore, Storage, Functions, Emulators
├── firestore.rules                            # Zero-trust multi-tenant Firestore security rules
├── firestore.indexes.json                     # Composite Firestore query indexes
├── storage.rules                              # Tenant-scoped Firebase Storage security rules
├── functions/                                 # Cloud Functions v2 Firestore triggers (Emulator/Blaze)
├── backend/
│   ├── main.py                                # FastAPI gateway, auth endpoints, Prometheus /metrics
│   ├── config.py                              # Pydantic Settings (JWT, HKDF, Firebase, FL, DP)
│   ├── auth.py                                # Firebase ID token + App Check + JTI-revoked JWT auth
│   ├── isolation.py                           # Salted HKDF, AES-256-GCM AAD, fail-closed guards
│   ├── firebase_client.py                     # Firebase Admin SDK (Cloud / Emulator / Local fallback)
│   ├── repositories.py                        # 11-collection Firestore sync & audit integrity hash
│   ├── storage_service.py                     # Firebase Storage + local AES-256-GCM fallback
│   ├── database.py                            # SQLAlchemy 2.0 async local/mirror models
│   ├── middleware.py                          # ContextVar cleanup, leakage scan, rate limiting
│   ├── metrics.py                             # Prometheus metrics registry
│   ├── response_engine.py                     # Threat escalation & admin approval gate engine
│   ├── schemas.py                             # Strict Pydantic v2 schemas
│   ├── db/init.sql                            # PostgreSQL extension initialization
│   ├── Dockerfile                             # Root-context production API image
│   └── routers/                               # admin, audit, cicd, federated, responses, system, tenants, threats
├── federated_learning/
│   ├── data_simulator.py                      # 5-tenant non-IID 19-feature telemetry generator
│   ├── model.py                               # LSTMThreatDetector (19-in) & AutoencoderDetector
│   ├── privacy.py                             # Validated RDP Moments Accountant & X25519 Pairwise SecAgg
│   ├── aggregation.py                         # Krum, Trimmed Mean, FedAvg, MAD outlier detection
│   ├── client.py                              # Flower client (L2 clipping + DP noise + TLS)
│   ├── server.py                              # Flower server (TLS + Prometheus :8081 + checkpoints)
│   ├── fl_runner.py                           # In-process 5-client Flower FL training orchestrator
│   ├── ml_benchmark.py                        # LSTM vs RF vs XGBoost benchmark & inference engine
│   ├── explainability.py                      # SHAP / Gradient x Input XAI engine
│   ├── pipeline_security.py                   # SAST secret/CVE regex scanner & feature extractor
│   └── Dockerfile                             # Root-context Flower FL server/client image
├── frontend/
│   ├── index.html                             # 14-module SOC dashboard
│   ├── css/styles.css                         # Glassmorphic dark-navy + light mode styles
│   ├── js/{api,app,charts,firebase-config,firebase-sdk}.js
│   ├── Dockerfile & nginx.conf                # Nginx container with CSP & SSE proxy
├── monitoring/                                # Prometheus config, alert rules, Grafana provisioning
├── scripts/                                   # run_simulation.py, setup.ps1, setup.sh
├── tests/                                     # Pytest suites + firebase_rules.test.mjs
├── requirements.txt & requirements-dev.txt
├── docker-compose.yml                         # Postgres, FL server, 5 clients, API, Frontend, Prom, Grafana
└── docs: API_DOCUMENTATION.md, DATABASE_SCHEMA.md, DEPLOYMENT_GUIDE.md, FIREBASE_SETUP_GUIDE.md,
          SECURITY_MODEL.md, TESTING_REPORT.md, RESEARCH_EVALUATION.md
```

---

## Quick Start

### 1. Local Python Run (Fastest — Zero Cloud Cost)
```powershell
.\scripts\setup.ps1
C:\Users\shanm\Python311\python.exe scripts\run_simulation.py
.\start_backend.bat
```
Open **http://localhost:8000** (API docs: **http://localhost:8000/docs**, Metrics: **http://localhost:8000/metrics**).

### 2. Firebase Emulators or Cloud Hosting
See [FIREBASE_SETUP_GUIDE.md](FIREBASE_SETUP_GUIDE.md) and [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md).

### 3. Run Security & Automated Tests
```powershell
C:\Users\shanm\Python311\python.exe -m pytest tests/ --cov=backend --cov=federated_learning -v
C:\Users\shanm\Python311\python.exe -m bandit -r backend federated_learning scripts -ll -ii
```
