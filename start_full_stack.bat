@echo off
title SecureFL Full Stack (Docker Compose)
echo ========================================================
echo  SecureFL — Multi-Tenant DevSecOps & Federated Learning
echo ========================================================
echo.
echo Launching local compute + monitoring services via Docker Compose:
echo   - PostgreSQL (Local Fallback/Mirror DB)
echo   - Flower FL Aggregation Server (:8080, Prometheus :8081)
echo   - 5 Isolated Tenant FL Clients (Alpha, Beta, Gamma, Delta, Epsilon)
echo   - FastAPI Security Gateway (:8000)
echo   - Web Dashboard (:3000)
echo   - Prometheus (:9090) & Grafana (:3001)
echo.
docker compose up --build
pause
