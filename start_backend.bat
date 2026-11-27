@echo off
title Multi-Tenant Cloud Security Backend
echo ========================================================
echo  Starting FastAPI Security Gateway (Port 8000)
echo ========================================================
echo.

set PY="C:\Users\shanm\Python311\python.exe"
if exist %PY% (
    %PY% -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
) else (
    python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
)
pause
