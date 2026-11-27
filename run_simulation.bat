@echo off
title Multi-Tenant FL Security Simulation
echo ========================================================
echo  Multi-Tenant Cloud Threat Detection Simulation
echo ========================================================
echo.
echo Running end-to-end experimental evaluation...
set PY="C:\Users\shanm\Python311\python.exe"
if exist %PY% (
    %PY% scripts\run_simulation.py
) else (
    python scripts\run_simulation.py
)
echo.
pause
