# Deployment Guide — Hybrid Firebase + Local Python / Docker

## Option A: Local Python Development (Zero Dependencies on Docker/Blaze)
```powershell
# 1. Install dependencies
C:\Users\shanm\Python311\python.exe -m pip install -r requirements.txt

# 2. Generate 5-tenant non-IID telemetry & copy .env
.\scripts\setup.ps1

# 3. Run full comparative ML + 5-client Flower FL simulation
C:\Users\shanm\Python311\python.exe scripts\run_simulation.py

# 4. Start FastAPI Gateway & Open http://localhost:8000
.\start_backend.bat
```

## Option B: Docker Compose Full Local Compute Stack
Starts PostgreSQL, Flower FL Server (`:8080`, Prometheus `:8081`), 5 isolated tenant FL client containers (`tenant-a-client`..`tenant-e-client`), FastAPI API Gateway (`:8000`), Nginx Frontend (`:3000`), Prometheus (`:9090`), and Grafana (`:3001`):
```powershell
docker compose up --build -d
docker compose ps
```

## Option C: Production Firebase Hosting + Local/Cloud Compute
1. Follow [FIREBASE_SETUP_GUIDE.md](FIREBASE_SETUP_GUIDE.md) to initialize your Firebase project and `.firebaserc`.
2. Deploy Firestore rules, indexes, and the responsive cybersecurity dashboard:
   ```powershell
   firebase deploy --only firestore:rules,firestore:indexes,hosting
   ```
3. Run the Python FastAPI + Flower FL coordinator locally (or later migrate to Google Cloud Run / GKE with Secret Manager when cloud compute funding is available).
