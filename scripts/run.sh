#!/usr/bin/env bash
# Linux/macOS equivalent of run.ps1 (Mohamed Kassem). Usage: scripts/run.sh <service>
set -euo pipefail
cd "$(dirname "$0")/.."
declare -A PORTS=([users]=8001 [logs]=8005 [notifications]=8008 [threats]=8004 [reports]=8006 [vulnerabilities]=8007)
service="${1:-}"
if [[ -z "${PORTS[$service]:-}" ]]; then
    echo "Usage: $0 {users|logs|notifications|threats|vulnerabilities|reports}" >&2
    exit 1
fi
if [[ -f .env ]]; then set -a; source .env; set +a; fi
exec .venv/bin/python -m uvicorn "services.$service.app:create_app" --factory --host 127.0.0.1 --port "${PORTS[$service]}"
