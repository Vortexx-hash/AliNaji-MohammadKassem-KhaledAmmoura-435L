# Sprint 1 backend (Ali Naji)

Ali Naji owns Threat Intelligence (Service 4), Vulnerability Management (Service 7), and Security Reports (Service 6). Work is isolated on `ali-naji/sprint1-services`. The six other services remain the responsibility of Mohammad Kassem and Khaled Ammoura. No frontend is required.

Python 3.10+ and SQLite run locally without Docker or a database server. Services run in separate processes and communicate through HTTP. All routes, including documentation, begin with `/AliNaji` (full name with spaces removed).

## Setup (Ali Naji)

Run PowerShell in the repository:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
$env:JWT_SECRET = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
.\.venv\Scripts\python.exe -m scripts.dev_tokens --postman
.\.venv\Scripts\python.exe -m uvicorn services.threats.app:create_app --factory --host 127.0.0.1 --port 8004
```

Keep the same `JWT_SECRET`, issuer, and audience in each service terminal. `.env.example` documents configuration; it is not automatically loaded. Never commit secrets, local tokens, or populated databases.

Open `http://127.0.0.1:8004/AliNaji/docs` for interactive API schemas. Import the collection and local environment in `postman/`. Local tokens expire after 30 minutes; regenerate when needed. They test bearer verification and role enforcement, not login/password verification. Actual login belongs to the teammate's Users service.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Databases and their tables are created on service startup under `data/`; SQL sources are in `database/`. See [API documentation](docs/api.md), [integration contracts](docs/integration.md), and [database design](docs/database.md).
