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
