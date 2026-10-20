#!/usr/bin/env bash
# Linux/macOS equivalent of setup_local.ps1 (Mohamed Kassem).
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -x .venv/bin/python ]] || python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
if [[ ! -f .env ]]; then
    echo "JWT_SECRET=$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(48))')" > .env
fi
if ! grep -q '^AUDIT_SERVICE_TOKEN=' .env; then
    echo "AUDIT_SERVICE_TOKEN=$(.venv/bin/python -m scripts.service_token)" >> .env
fi
set -a; source .env; set +a
.venv/bin/python -m scripts.dev_tokens --postman
echo "Local configuration ready. Start a service with: scripts/run.sh users"
