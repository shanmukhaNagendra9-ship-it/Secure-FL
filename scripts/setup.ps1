# Windows PowerShell Setup Script for SecureFL Platform
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "SecureFL Multi-Tenant Cloud Security & Firebase Setup" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$dirs = @("data\tenant_a","data\tenant_b","data\tenant_c","data\tenant_d","data\tenant_e","models","metrics","logs","artifacts")
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "[+] Created .env from .env.example — set JWT_SECRET_KEY, TENANT_MASTER_KEY, and Firebase keys." -ForegroundColor Green
}

$py = "C:\Users\shanm\Python311\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

Write-Host "[*] Generating 5-tenant non-IID synthetic telemetry..." -ForegroundColor Yellow
& $py -m federated_learning.data_simulator --samples 3000 --outdir data
Write-Host "[✓] Setup complete. Start API Gateway with .\start_backend.bat" -ForegroundColor Cyan
