# Test now with synthetic dependencies (Ali Naji)

The standalone demo lets you test all three assigned services before teammates finish their APIs. Your actual Threat Intelligence, Vulnerability Management, and Reports code runs with separate SQLite databases. Explicit fixture endpoints supply the missing users, assets, incidents, and initial activities. A demo audit receiver stores the actual events emitted by your APIs alongside clearly marked synthetic activity examples. This is local development support, not an implementation of teammates' services or proof of their integration.

## Start (Ali Naji)

From the repository root, after installing the project's dependencies:

```powershell
.\.venv\Scripts\python.exe -m scripts.demo start
```

If `.venv` does not exist, run `.\scripts\setup_local.ps1` first. Keep the demo launcher running. It starts all four local processes, waits for them to become ready, creates sample records through your actual APIs, and writes an importable Postman environment. Normal mode on ports 8004/8007/8006 can remain running at the same time.

| Demo process | Port | Documentation |
| --- | --- | --- |
| Actual Threat Intelligence | 8104 | http://127.0.0.1:8104/AliNaji/docs |
| Actual Vulnerability Management | 8107 | http://127.0.0.1:8107/AliNaji/docs |
| Actual Security Reports | 8106 | http://127.0.0.1:8106/AliNaji/docs |
| Synthetic dependency fixtures | 8010 | http://127.0.0.1:8010/AliNaji/demo/docs |

All demo responses carry `X-Lab-Mode: synthetic-dependencies`. Interactive docs are labelled DEMO. No normal-mode configuration or databases are changed. Stopping demo dependencies produces ordinary dependency errors; the service code has no fallback that silently invents records.

## Use Postman (Ali Naji)

1. Import `postman/AliNaji.demo.environment.local.json`.
2. Select **Ali Naji - DEMO with SYNTHETIC dependencies** as the active environment.
3. Import the existing Threats, Vulnerabilities, and Reports collections. No collection edits are needed because their base URLs come from the selected environment.
4. Run any collection in order, including the entire Reports collection. Use `asset_id = 1`, `2`, or `3`. An unknown id still returns 404; invalid inputs, skipped lifecycle steps, expired tokens, and forbidden roles still fail normally.

**Vulnerability creation now works in this environment:** the actual service verifies asset 1 against the explicit fixture endpoint, inserts a real local asset reference and vulnerability with an enforced foreign key, returns 201, and emits an actual demo audit event. You can retrieve, update, search, progress through the lifecycle, and delete that record using your normal APIs.

The Postman collections create and delete their own temporary records. The demo also creates persistent samples: four threats with different severities and five vulnerabilities spanning Open, Under Investigation, In Progress, Resolved, and Closed. Seeded findings use synthetic CVE-format identifiers and make no claim about actual CVE applicability.

## Sample data and persistence (Ali Naji)

`demo/fixtures.json` contains four synthetic users (one per role), three synthetic assets, five synthetic incidents (one per status), and three explicitly synthetic login activity examples. There is no registration/login/password service. Development tokens are generated locally; initial login activity examples are not evidence that real users logged in.

`data/demo/services/threats.db` and `vulnerabilities.db` contain real records created by calling your running services. `reports.db` contains their normal audit transport tables. `demo_dependencies.db` stores fixture and received activity rows. The `origin` column distinguishes `synthetic_fixture` from `actual_demo_api_event`.

Startup preserves existing demo databases and avoids re-adding matching seeded records; your manual test records remain available after restart. You can inspect the separate SQLite files with DB Browser or:

```powershell
.\.venv\Scripts\python.exe -m scripts.inspect_db vulnerabilities --data-dir data/demo/services
```

Logs, the demo signing key, runtime state, and databases stay under the ignored `data/demo/` directory. Generated Postman tokens are ignored as well. The demo uses a separate signing key, issuer, and audience from normal mode.

## Refresh tokens and stop (Ali Naji)

Postman tokens last two hours. To refresh, run this in another repository terminal, reimport the generated environment, and select it:

```powershell
.\.venv\Scripts\python.exe -m scripts.demo tokens
```

The demo audit sender has a 24-hour token; restart the demo for a longer session. Stop with Ctrl+C in its launcher, or from another terminal:

```powershell
.\.venv\Scripts\python.exe -m scripts.demo stop
```

This sends a stop request to the matching demo run and terminates only its child processes. It preserves demo data and leaves normal services running. A busy port fails startup rather than stopping some other process.

## Command line verification (Ali Naji)

Each command runs the exact same collection you can import in Postman:

```powershell
npx.cmd --yes newman@6.2.1 run postman/AliNaji.threats.postman_collection.json -e postman/AliNaji.demo.environment.local.json
npx.cmd --yes newman@6.2.1 run postman/AliNaji.vulnerabilities.postman_collection.json -e postman/AliNaji.demo.environment.local.json
npx.cmd --yes newman@6.2.1 run postman/AliNaji.reports.postman_collection.json -e postman/AliNaji.demo.environment.local.json
```

These runs verify your actual APIs and persisted demo records with simulated upstream data. Clearly identify that dependency setup in any screenshots/report. They do not establish real Users/Assets/Incidents/Logs implementation or integration, and synthetic login examples do not replace the assignment's real login evidence. Use normal mode and actual teammate URLs when those services are ready.

Verification completed: all three full collections passed against the running demo, with **86 requests and 104 assertions, zero failures** (Threats 28/31; Vulnerabilities 31/33; Reports 27/40). The automated suite passed **102 tests**, including actual owned-service CRUD, all six report calculations over fixture sources, audit delivery, fixture permissions, idempotent events, and preserved fixture data on restart. The launcher's stop/restart behavior was also checked; normal-mode services remain separate.
