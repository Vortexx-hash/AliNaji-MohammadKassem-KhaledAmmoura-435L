# Sprint 1 backend (Ali Naji)

Ali Naji owns Threat Intelligence (Service 4), Vulnerability Management (Service 7), and Security Reports (Service 6). Work is isolated on `ali-naji/sprint1-services`. The six other services remain the responsibility of Mohammad Kassem and Khaled Ammoura. No frontend is required.

Read the [implementation handoff](docs/HANDOFF.md) for completed features, verification results, commits, and the remaining teammate integration/submission tasks.

**Test everything before teammates finish:** run `.\.venv\Scripts\python.exe -m scripts.demo start` and select `postman/AliNaji.demo.environment.local.json` in Postman. This runs your actual APIs on separate ports with explicitly synthetic dependencies and separate databases. Vulnerability creation and all six reports work in this demo. See the [demo instructions](docs/demo.md).

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

## Vulnerability Management (Ali Naji)

Use the helper scripts to share the ignored local configuration between terminals:

```powershell
.\scripts\setup_local.ps1
# Add ASSET_DETAIL_URL=http://127.0.0.1:<port>/<TeammateFullName>/assets/{id} to .env
.\scripts\run.ps1 vulnerabilities
```

The service runs on port 8007. Set Postman's `asset_id` to a real asset created by your teammate. Creation verifies that asset over HTTP and saves a local reference with a real foreign key. With no Assets API configured, creation returns 503; other operations remain testable. The test suite uses isolated mock HTTP fixtures for successful asset lookup, not fake production assets. Import `AliNaji.vulnerabilities.postman_collection.json` and run requests in order after configuring the real dependency.

## Security Reports (Ali Naji)

```powershell
.\scripts\run.ps1 reports
```

Reports run on port 8006. Start Threat Intelligence and Vulnerability Management first. Threat/vulnerability reports work immediately against those real APIs, including correctly reporting zero vulnerabilities before the Assets dependency is ready. Summary/incident/asset/activity reports additionally need the teammate URLs in `.env.example`. Missing sources return 503, never invented counts. There is no report table because reports derive live data without persisting report snapshots; `reports.db` contains only durable audit transport tables.

Generate sample threat records through your running API:

```powershell
.\.venv\Scripts\python.exe -m scripts.seed_owned
# After a real asset exists, optionally seed vulnerabilities too:
.\.venv\Scripts\python.exe -m scripts.seed_owned --asset-id 7
.\.venv\Scripts\python.exe -m scripts.inspect_db threats
```

The optional asset id above is an example: use the id actually created by your teammate. The default sample seeder is repeatable for threats (409 duplicates are accepted); optional vulnerability seeding creates new records on each run.

Import all three Postman collections and `AliNaji.environment.local.json`. Run vulnerability requests after configuring the real asset service. In the Reports collection, `Available own services` and `Access control` folders work with only our three processes; `Team dependent reports` needs the other services. The CRUD collections clean up the records they create. Seed samples separately when capturing database screenshots.

Optional command-line execution of the exact Postman requests:

```powershell
npx.cmd --yes newman@6.2.1 run postman/AliNaji.threats.postman_collection.json -e postman/AliNaji.environment.local.json
npx.cmd --yes newman@6.2.1 run postman/AliNaji.reports.postman_collection.json -e postman/AliNaji.environment.local.json --folder "Available own services" --folder "Access control"
```

To refresh local Postman tokens, run `.\scripts\setup_local.ps1` again. Stop/restart service terminals after changing `.env`; the launcher loads it at startup. The API health and documentation URLs use the same `/AliNaji` prefix in every service.
