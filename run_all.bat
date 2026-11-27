@echo off
title SecureFL Cloud Security Launcher
echo ========================================================
echo  SecureFL — Multi-Tenant Cloud Security & Federated AI
echo ========================================================
echo.
echo [1/2] Starting FastAPI Security Gateway on http://localhost:8000 ...
start "SecureFL FastAPI Gateway (:8000)" cmd /c "set PY=C:\Users\shanm\Python311\python.exe && if exist %PY% (%PY% -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload) else (python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload) && pause"

timeout /t 3 /nobreak >nul
echo [2/2] Opening SecureFL Dashboard at http://localhost:8000 ...
start "" "http://localhost:8000"
echo API Docs available at http://localhost:8000/docs
pause
