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

## Vulnerability Management (Ali Naji)

Base URL: `http://127.0.0.1:8007/AliNaji`.

| API | Method and path | Parameters/body | Success |
| --- | --- | --- | --- |
| Add vulnerability | `POST /vulnerabilities` | All seven fields in create example | 201 vulnerability object |
| Retrieve all | `GET /vulnerabilities` | None | 200 array |
| Retrieve specific | `GET /vulnerabilities/{id}` | Positive integer id | 200 object |
| Update vulnerability | `PUT /vulnerabilities/{id}` | One or more of description, severity, status, cvss_score, resolution_date | 200 updated object |
| Search vulnerabilities | `GET /vulnerabilities/search` | Optional cve_identifier, severity, affected_asset_id, status; exact matches combined with AND | 200 array, empty when no matches |
| Delete vulnerability | `DELETE /vulnerabilities/{id}` | Positive integer id | 204 empty body |

```json
{"title":"Lab web service weakness","description":"Lab finding requiring remediation","cve_identifier":"CVE-2025-12345","cvss_score":8.1,"severity":"High","affected_asset_id":7,"discovery_source":"Lab scanner"}
```

The create response adds integer `id`, `status: "Open"`, UTC `creation_date`, and `resolution_date: null`. CVE format is `CVE-YYYY-NNNN` with four or more sequence digits (normalized uppercase; existence in an external CVE catalog is not claimed). CVSS must be a JSON number from 0 to 10, not a string or Boolean. Severity uses Low/Medium/High/Critical and remains an explicit assessment independent of CVSS. No duplicate-CVE restriction exists because one CVE can affect several assets. Title/source are nonempty strings up to 255 characters; description up to 4000; asset id is a positive integer that must exist in the real Assets service.

Lifecycle: `Open -> Under Investigation -> In Progress -> Resolved -> Closed`. Updates may keep the current state, move one step forward, and change other allowed fields; skips/reversals return 409. Entering Resolved sets resolution_date to current UTC automatically. A supplied date must include a timezone and fall between creation and now; dates on unresolved records are rejected. Closing preserves the resolution timestamp. The asset/CVE/title/source and creation timestamp remain unchanged on updates.

Administrator can perform every operation. Analyst can list/get/search/update. Auditor can list/get/search. Regular Employee/User has no access. Deletion always requires Administrator.

## Security Reports (Ali Naji)

Base URL: `http://127.0.0.1:8006/AliNaji`. All six APIs are GET with no required query/body parameters. Only Security Administrator and Auditor can generate reports; Analyst and Employee requests return 403. Every success is HTTP 200 with a JSON object. Every object includes `generated_at` (UTC ISO timestamp) and `sources` (names of source services used). A missing, unreachable, invalid, duplicate, or incomplete source dataset returns 503 for the entire report.

| API and path | Data sources | Returned fields besides metadata |
| --- | --- | --- |
| Generate security summary, `/reports/summary` | users, assets, incidents, threats, vulnerabilities, logs | users, assets, incidents, open_incidents, unresolved_incidents, incidents_by_severity, threats, critical_threats, vulnerabilities, critical_vulnerabilities, recent_security_activities |
| Generate incident report, `/reports/incidents` | incidents | total_incidents, incidents_by_severity, incidents_by_status |
| Generate asset report, `/reports/assets` | assets | total_assets, critical_assets, assets_by_type |
| Generate threat report, `/reports/threats` | threats | total_threats, threats_by_severity, threats_by_type, recent_added_threats |
| Generate vulnerability report, `/reports/vulnerabilities` | vulnerabilities | total_vulnerabilities, vulnerabilities_by_severity, vulnerabilities_by_status, critical_vulnerabilities |
| Generate activity report, `/reports/activity` | logs | total_user_activities, login_attempts, failed_login_attempts, most_performed_actions, recent_security_activities |

Counts are integers. Group distributions map enum/type names to counts. Severity/status/type enum groups include zero-valued categories. Asset type groups contain the types present in source data. `open_incidents` counts the literal Open status; `unresolved_incidents` additionally includes Under Investigation and Mitigated. Critical vulnerability counts include records in all statuses; status groups let users distinguish remediated records. Recent threat/activity lists contain at most ten records sorted newest first using timezone-aware timestamps. Source records are projected to report fields; user/password data are never returned.

Activity `login_attempts` is the count of `LOGIN_SUCCESS` plus `LOGIN_FAILED` events; `failed_login_attempts` counts `LOGIN_FAILED`. Authentication failures on already protected resources are separate events. Most performed actions returns up to ten `{action,count}` objects ordered by descending count and then action name. These event names are an explicit team integration contract.

Example response shape for an empty threat dataset (documentation only):

```json
{"generated_at":"2026-10-19T20:00:00+00:00","sources":["threats"],"total_threats":0,"threats_by_severity":{"Low":0,"Medium":0,"High":0,"Critical":0},"threats_by_type":{"IP Address":0,"Domain":0,"File Hash":0,"Malware Signature":0,"Other Indicators":0},"recent_added_threats":[]}
```

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
