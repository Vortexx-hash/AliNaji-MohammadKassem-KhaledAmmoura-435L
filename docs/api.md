# API documentation (Ali Naji)

Every protected request requires `Authorization: Bearer <token>`. Request/response content type is JSON. Full machine-readable field definitions and examples of allowed enum values appear at each service's `/AliNaji/openapi.json`; interactive documentation is at `/AliNaji/docs`.

## Threat Intelligence (Ali Naji)

Base URL: `http://127.0.0.1:8004/AliNaji`.

| API | Method and path | Parameters/body | Success |
| --- | --- | --- | --- |
| Add threat indicator | `POST /threats` | All five fields below | 201 threat object |
| Retrieve all indicators | `GET /threats` | None | 200 array of threat objects |
| Retrieve indicator | `GET /threats/{id}` | Positive integer id | 200 threat object |
| Search indicators | `GET /threats/search` | Optional exact case-insensitive `threat_type`, `threat_value`, `severity`, `source`; combined with AND | 200 array, `[]` if no matches |
| Update information | `PUT /threats/{id}` | Positive id; one or more of `description`, `severity`, `source` | 200 updated object |
| Delete indicator | `DELETE /threats/{id}` | Positive id | 204 empty body |

Create body:

```json
{"threat_type":"IP Address","threat_value":"203.0.113.8","description":"Lab scanning indicator","severity":"High","source":"Lab sensor"}
```

A returned object adds `id` (integer) and `date_added` (UTC ISO 8601 timestamp). Description is trimmed, nonempty, at most 4000 characters. Source/value are trimmed, nonempty, at most 255 characters. Types: `IP Address`, `Domain`, `File Hash`, `Malware Signature`, `Other Indicators`. Severities: `Low`, `Medium`, `High`, `Critical`. IP values accept IPv4/IPv6; domains accept ASCII hostnames (punycode for international names) without schemes/paths; hashes accept hexadecimal MD5/SHA-1/SHA-256. Domain case/trailing dots, hash case, and IPv6 spelling are normalized before the database uniqueness check on `(threat_type, threat_value)`.

Only Security Administrator can create/update/delete. Administrator, Security Analyst, and Auditor can list/get. Administrator and Analyst can search. The general role description grants auditor search, but Service 4's explicit authorization list omits it; this implementation follows that narrower list. Confirm this inconsistency with the instructor before changing permissions. Regular Employee/User has no access.

## Errors (Ali Naji)

All errors use `{"status":"error","message":"..."}`. Validation errors also contain `errors`, an array of `{field,message}`. No SQL statements, secrets, token contents, or stack traces appear in responses.

| HTTP | Meaning |
| --- | --- |
| 401 | Missing/invalid/expired token, invalid role, inactive/suspended account |
| 403 | Authenticated role lacks permission |
| 404 | Requested record does not exist |
| 409 | Duplicate indicator or invalid lifecycle transition |
| 422 | Invalid body/query/id, missing or unknown fields, blank/null update |
| 503 | Required dependency or database unavailable |
| 500 | Unexpected internal failure |

Updates preserve unspecified fields. Unknown request-body and search fields are rejected. SQL values are parameterized. Error and permission checks apply before repository operations. Automatic security events are queued durably; see integration documentation.
