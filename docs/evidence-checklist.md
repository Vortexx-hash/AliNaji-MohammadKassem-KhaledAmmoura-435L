# Execution evidence checklist (Ali Naji)

The assignment requires real screenshots of Postman requests/responses and database records. This repository provides executable collections and test tools. No screenshots have been fabricated or supplied as if they came from Postman. Automated fixtures prove behavior under controlled inputs; they are not proof that a teammate's unfinished service exists.

## Prepare actual Postman captures (Ali Naji)

1. Run `scripts/setup_local.ps1`, then start all three owned services with `scripts/run.ps1` in separate terminals. Import the three collections and the ignored local environment. Select that environment. Tokens expire after 30 minutes; refresh them when needed.
2. Run the Threat Intelligence collection in order. Pause before its delete requests to capture rows in `data/threats.db`. The final delete requests remove the temporary records. `scripts.seed_owned` creates four persistent lab samples through the real API for later captures.
3. Configure the real Assets endpoint, create an asset through your teammate's API, and set Postman's `asset_id` accordingly. Run the Vulnerability Management collection in order, taking captures before cleanup. Capture each workflow transition and the resolution date. To retain separate sample findings, run `scripts.seed_owned --asset-id <real-id>` after collection cleanup.
4. Configure the real Users/Assets/Incidents/Logs list endpoints. Create varied incidents, assets, users, and activities through the owners' APIs. Run the complete Reports collection. Before that integration exists, only its `Available own services` and `Access control` folders are expected to succeed.
5. Open each SQLite database in DB Browser for SQLite, or use `python -m scripts.inspect_db threats` / `vulnerabilities` / `reports`. Capture schema, records, primary/foreign keys, and query results that reconcile with report totals. Read-only report generation does not require a saved Reports business table.
6. Show actual successful/failed login using the teammate's Users service, then use those returned tokens for an allowed/denied request pair. Local development tokens are not evidence of login/password verification. Configure the audit sink, retry outbox delivery, and capture the events in the actual Logs service/database.

Each screenshot caption must include **Ali Naji**, the API title, and what the call does. Show HTTP method, full named route, request body or query, status code, and response; do not expose bearer tokens/secrets. Example caption: `Ali Naji - Update Vulnerability Information - advances an investigated finding to In Progress and returns the stored status`.

## Capture matrix (Ali Naji)

| Service | Required scenarios |
| --- | --- |
| Threat Intelligence | Multiple types/severities; database rows; list/get; missing id; searches by type/value/severity/source; update before/after; duplicate rejection; invalid IP/domain/hash/severity/missing fields; administrator delete; analyst delete denied |
| Vulnerability Management | Multiple severities/statuses; verified affected asset and FK; list/get/missing id; CVE/severity/asset/status searches; detail update before/after; every allowed transition; rejected skip/reversal; resolution timestamp; invalid CVE/CVSS/asset/severity/missing fields; admin delete; analyst delete denied |
| Security Reports | All six reports over real system data; threat/vulnerability counts reconciled with database rows; incident severity/status counts; asset type/critical counts; real login/failure activities; administrator/auditor allowed; analyst/employee denied; missing source errors |
| Shared security | Real successful/failed login from Users owner; allowed/denied role pair; expired/missing token; permission denial and modification events delivered to the Logs owner's service |
| Git | Feature branch history; the three service commits; individual author contribution; eventual team integration/merge evidence |

Keep screenshots in `evidence/local/` while preparing the shared report. This ignored directory can contain local execution material; choose and review the final captures before intentionally adding them to the common submission. Do not publish environment files, bearer tokens, secrets, or raw Newman JSON reports containing Authorization headers.

`python -m scripts.verify_live` saves token-free real report responses to `evidence/local/live-verification.json` and checks them against our live database rows. This is useful supplemental CLI evidence, not a substitute for required Postman screenshots.
