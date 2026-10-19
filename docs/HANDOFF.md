# Sprint 1 implementation handoff (Ali Naji)

Ali Naji's three assigned services are implemented on `ali-naji/sprint1-services`: Threat Intelligence, Vulnerability Management, and Security Reports. They expose 18 required business endpoints, all named with `/AliNaji`, plus named health/documentation endpoints. The other six services have no implementations or business tables in this branch. Main has not been merged or pushed.

## Implemented scope (Ali Naji)

| Service | Implementation | Database | Postman |
| --- | --- | --- | --- |
| Threat Intelligence | Create/list/get/search/update/delete; five indicator types; four severities; IP/domain/hash validation; canonical duplicate protection; role enforcement | threats.db: threats plus audit transport tables | 28 requests, including CRUD, searches, invalid inputs, duplicates, authentication and role failures |
| Vulnerability Management | Create/list/get/update/search/delete; CVE/CVSS checks; verified asset association; full ordered remediation workflow; resolution dates; role enforcement | vulnerabilities.db: vulnerabilities, asset_references, audit transport tables | 31 requests, including complete workflow and denied/invalid requests |
| Security Reports | Summary, incident, asset, threat, vulnerability, activity reports; real HTTP sources; distributions, critical counts and recent records; strict source validation | reports.db: audit transport tables; reports derive current data and require no new business table | Three folders: owned live sources, teammate-dependent reports, access control |

Shared support includes signed JWT verification, optional live identity checks, consistent JSON errors, bound SQL parameters, transaction handling, database FK/CHECK/uniqueness/transition constraints, and immutable audit events with retryable delivery. Local development tokens have a 30-minute expiry and are explicitly separate from real user login. Database contents and secrets remain local/ignored; source SQL is versioned.

## Verification performed (Ali Naji)

- **100 automated tests passed.** Tests cover all three services, every role, record persistence, duplicate normalization, indicator/CVE/CVSS input validation, foreign keys, complete vulnerability lifecycle, invalid transitions, resolution times, exact report calculations, zero datasets, broken/malformed/partial dependencies, JWT signature/claims, live identity-check behavior, and audit outage/retry. External service success cases use isolated HTTP fixtures, not fabricated production services.
- **Threat collection on the running service:** 28 actual HTTP requests, 31 assertions, zero failures.
- **Report collection against running owned services:** 18 actual HTTP requests, 26 assertions, zero failures, covering the `Available own services` and `Access control` folders.
- **Actual SQLite reconciliation:** four lab threat records created through the API, with one each of Low/Medium/High/Critical; the live threat report matches record and severity counts. The vulnerability report correctly matches the empty real database while the Assets integration is unavailable.
- **Source integrity:** Python compilation, dependency compatibility (`pip check`), and Git whitespace checks passed. A third-party AnyIO/TestClient deprecation warning does not affect results.

Real token-free live responses are saved locally in `evidence/local/live-verification.json`. Newman CLI logs are also in that ignored folder. These are actual local execution results, not Postman GUI screenshots. Successful vulnerability creation and the complete six-source report integration have not been demonstrated against teammates' real services because those services are not yet implemented/configured.

## Start and test (Ali Naji)

From the repository root in PowerShell:

```powershell
.\scripts\setup_local.ps1
```

Open three repository terminals and run one command in each:

```powershell
.\scripts\run.ps1 threats
.\scripts\run.ps1 vulnerabilities
.\scripts\run.ps1 reports
```

| Service | Interactive docs | Database |
| --- | --- | --- |
| Threats | http://127.0.0.1:8004/AliNaji/docs | data/threats.db |
| Vulnerabilities | http://127.0.0.1:8007/AliNaji/docs | data/vulnerabilities.db |
| Reports | http://127.0.0.1:8006/AliNaji/docs | data/reports.db |

Import the three `postman/AliNaji.*.postman_collection.json` files and select `postman/AliNaji.environment.local.json`. The environment template without `.local` is versioned with empty token fields. Refresh development tokens by rerunning setup; use actual login tokens after the Users integration is ready.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m scripts.seed_owned
.\.venv\Scripts\python.exe -m scripts.inspect_db threats
.\.venv\Scripts\python.exe -m scripts.verify_live
```

The local secret is shared by the three launchers through the ignored `.env`. Do not regenerate/replace it in only one service terminal. Restart services after changing configuration.

## Team integration still required (Ali Naji)

1. **Users owner:** provide login and token issuance. Agree on the JWT contract; set `IDENTITY_ME_URL` for immediate role/account-status checks. Current signed-claim verification works independently but cannot discover revocation before token expiry without that endpoint. Password hashing and successful/failed real-login evidence belong to the Users implementation.
2. **Assets owner:** provide a real asset and `ASSET_DETAIL_URL` containing `{id}`. Vulnerability creation deliberately returns 503 until this exists; no asset CRUD or fake asset catalog was implemented. Set Postman's `asset_id` to the real id before running the vulnerability collection. Our local FK references a verified asset projection; canonical asset deletion coordination remains a team integration decision.
3. **Logs owner:** provide `AUDIT_POST_URL`, an authorized `AUDIT_SERVICE_TOKEN`, and the documented idempotency/event contract. Existing events remain queued locally until delivery. Run the flush helper for threats, vulnerabilities, and reports, then verify them in the actual Logs service. The local outbox is not a replacement for Logs.
4. **Report sources:** configure `USERS_LIST_URL`, `ASSETS_LIST_URL`, `INCIDENTS_LIST_URL`, and `LOGS_LIST_URL` using each owner's full-name prefix. Sources must return complete records in the documented shape. Missing sources return 503 rather than fake zeros. Once configured, run `Team dependent reports` and compare its statistics with the owners' actual records.
5. **Submission:** capture real Postman/database/Git screenshots, integrate these implementation notes into the common team report with `(Ali Naji)` on owned sections, add the other members' sections/evidence, and complete the required CREATES meeting at least three days before the actual deadline. The assignment requires a common report and contribution evidence from all three members; those team-wide deliverables are not invented here. See the AI-assistance disclosure and assignment constraint in [references](references.md).

The assignment is inconsistent about auditor threat search. Its general role description permits it, while Service 4's explicit authorization list omits it. The implementation follows the narrower Service 4 list, so Auditor can list/get threats but cannot search. Confirm the intended rule with the instructor if needed.

## Commits and ownership (Ali Naji)

| Commit | Completed work |
| --- | --- |
| c800a83 | Threat Intelligence APIs, SQLite schema, authentication/audit support, tests and Postman collection |
| e8c286d | Vulnerability Management APIs, verified asset references, remediation lifecycle, tests and Postman collection |
| bd99484 | Six live security reports, HTTP source validation, security integration tests, Postman collection and documentation |

A final follow-up commit records validation hardening and this handoff. Git author remains the user's configured `Ali Naji`. No teammate attribution or contribution history is fabricated. The repository initially had no commits, so main has no committed history yet; only the feature branch is created/pushed here. Establishing the shared main branch and merging the services remains a later team action.

See [API details](api.md), [database design and ER diagrams](database.md), [architecture](architecture.md), [integration contracts](integration.md), [evidence checklist](evidence-checklist.md), and [references and AI disclosure](references.md).
