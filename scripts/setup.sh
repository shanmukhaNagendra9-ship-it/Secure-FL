#!/usr/bin/env bash
set -euo pipefail

mkdir -p data/tenant_a data/tenant_b data/tenant_c data/tenant_d data/tenant_e models metrics logs artifacts
if [ ! -f .env ]; then
  cp .env.example .env
  echo "[+] Created .env from .env.example"
fi

python3 -m federated_learning.data_simulator --samples 3000 --outdir data
echo "[OK] Setup complete."
