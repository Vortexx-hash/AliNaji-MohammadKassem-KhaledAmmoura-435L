# Team integration contracts (Ali Naji)

Ali Naji implements only Services 4, 6, and 7. No Users, Assets, Incidents, Logs, Notifications, or Playbooks APIs/tables are implemented here. Tests may replace dependency HTTP transports; those fixtures are not submission evidence.

## Identity and authorization (Ali Naji)

The teammate's login service should return an HS256 JWT signed using the team's private `JWT_SECRET` (minimum 32 characters). Required claims: nonempty string `sub` (user id), `role`, `account_status`, numeric `iat`, numeric `exp`, `iss` (`security-lab` by default), and `aud` (`security-services` by default). Exact roles: `Security Administrator`, `Security Analyst`, `Regular Employee/User`, `Auditor`. Only `Active` accounts are accepted. Algorithms are explicitly restricted to HS256. Adjust the adapter with the teammate if their contract differs.

Set `IDENTITY_ME_URL` to the teammate's authenticated current-user endpoint for immediate account/role revocation. It receives the caller's bearer token and returns `{id,role,account_status}` or `{data:{id,role,account_status}}`. Status 401/403/404 or a changed id/status/role rejects the token; unreachable/malformed responses fail closed with 503. Without this URL, signed claims are authoritative until expiry; no immediate suspension/revocation check is possible. `scripts.dev_tokens` is an explicitly local test helper, not a replacement identity service or proof of login.

## Audit delivery (Ali Naji)

Configure `AUDIT_POST_URL` with the teammate's full create-log URL (including their name) and `AUDIT_SERVICE_TOKEN` with an authorized service token. Events contain `user_id` (null for unknown caller), `action`, `description`, UTC `timestamp`, `severity`, and `related_service`. The sink must accept unknown callers and preserve the timestamp. It should deduplicate the UUID `Idempotency-Key` header because delivery is at least once.

Data changes and outbox insertion commit in one transaction. Permission/authentication failures create Warning events. The local immutable outbox is transport storage, not the Security Audit Logging Service. Delivery is attempted after writes/denials. Unavailable sinks never discard events or roll back already committed changes. Delivery receipts live separately. Retry backlog after configuring the sink:

```powershell
.\.venv\Scripts\python.exe -m scripts.audit_flush threats
```

The command sends up to 100 pending events per invocation; repeat until the health endpoint's pending count is zero. Do not treat undelivered events as proof of integration with the teammate's Logs service. The sink's API, permissions, and storage remain their responsibility.

## Asset association (Ali Naji)

Set `ASSET_DETAIL_URL` to the teammate's complete get-asset endpoint, with the literal `{id}` placeholder, e.g. `http://127.0.0.1:8002/MohammadKassem/assets/{id}` (illustrative only; the teammate chooses their port/prefix). The adapter forwards the authenticated caller's bearer token. Success must return `{id:7,asset_name:"..."}` or `{data:{id:7,asset_name:"..."}}`; `name` can substitute for asset_name. The id must be the same integer requested. Missing asset returns 404; missing URL, timeouts, upstream access rejection, malformed data, or errors return 503. A failed verification writes no vulnerability/reference record.

Only verified external asset identifiers are inserted into `asset_references`. Vulnerabilities have an enforced local FK to this projection. The canonical asset remains in the teammate's service; no cross-file FK is possible across independently owned databases. Creation always rechecks the live asset even if a reference was previously cached. References preserve history if the canonical asset is subsequently deleted. Coordinate canonical asset deletion with the team; a global database FK or distributed deletion transaction is not claimed. No asset CRUD endpoints or seed assets are added here.

Retry audit events for this service with `python -m scripts.audit_flush vulnerabilities` after loading `.env` values into the shell.

## Report sources (Ali Naji)

Set each `*_LIST_URL` to the full authorized endpoint (including its owner's name). The adapter forwards the caller's bearer token. Reports never access another service's SQLite file. The source must return a complete JSON array or `{data:[...],total:N}`. Counts are checked against total when present; pagination metadata, next pages, duplicate ids, missing fields, wrong enums, and naive timestamps are rejected with 503 rather than silently undercounting. If teammates choose paginated APIs, extend the adapter to fetch every page before deployment. Unknown extra record fields are ignored. No secrets from source users are included in report responses.

| Configuration | Fields required in each source record |
| --- | --- |
| USERS_LIST_URL | id (nonempty string or positive integer) |
| ASSETS_LIST_URL | id, asset_type, criticality_level (Low/Medium/High/Critical) |
| INCIDENTS_LIST_URL | id, severity, status (Open/Under Investigation/Mitigated/Resolved/Closed) |
| THREATS_LIST_URL | id, threat_type, threat_value, description, severity, source, timezone-aware date_added |
| VULNERABILITIES_LIST_URL | id, severity, status |
| LOGS_LIST_URL | id, action (or action_performed), description, timezone-aware timestamp, severity, related_service; optional user_id |

The owned threat/vulnerability URLs default to ports 8004/8007 with `/AliNaji` prefixes. Other URLs intentionally have no defaults because teammate names/ports/contracts are not established. The asset and incident list APIs must allow Administrator/Auditor; report access uses the requesting user's permissions, not an impersonated admin. Logs should use `LOGIN_SUCCESS` and `LOGIN_FAILED` actions for login counters and Information/Warning/Error/Critical severity strings. Agree on these contracts with the owners before shared integration testing.

Reports provide a live multi-service view, not a distributed transactional snapshot: records can change between source API reads. No result is returned if any required source fails. Each successful report generates its own audit event after collecting data; that event appears in subsequent activity reports once delivered. Retry with `python -m scripts.audit_flush reports` after loading configuration.
