@echo off
title Multi-Tenant Cloud Security Dashboard
echo ========================================================
echo  Multi-Tenant Cloud Data Isolation and Threat Detection
echo ========================================================
echo.
echo Launching Real Monitoring Platform in your default browser...
echo Target: http://localhost:8000
echo.
start "" "http://localhost:8000"
echo If port 8000 is not running, starting backend now...
timeout /t 2 /nobreak >nul
set PY="C:\Users\shanm\Python311\python.exe"
if exist %PY% (
    %PY% -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
) else (
    python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
)
pause
