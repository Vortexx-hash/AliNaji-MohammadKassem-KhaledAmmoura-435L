"""Generate version 2.1 collections; no tokens or invented execution evidence."""
import argparse
import json
import re
from pathlib import Path

SCHEMA = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"


def request(name, method, url, status=200, body=None, token="admin_token", checks=(), save=None, description="",
            author="Ali Naji", docs="docs/api.md"):
    test = [f"pm.test('HTTP {status}', () => pm.response.to.have.status({status}));"]
    test.extend(checks)
    if save:
        test.append(f"if (pm.response.code === {status}) pm.collectionVariables.set('{save}', pm.response.json().id);")
    req = {"method": method, "header": [], "url": url,
           "description": description or f"{name} ({author}). Expected HTTP {status}. See {docs} for fields and errors.",
           "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{" + (token or "") + "}}", "type": "string"}]}}
    if token is None:
        req["auth"] = {"type": "noauth"}
    if body is not None:
        req["header"] = [{"key": "Content-Type", "value": "application/json"}]
        raw = re.sub(r'"(\{\{\w+_id\}\})"', r'\1', json.dumps(body, indent=2))
        req["body"] = {"mode": "raw", "raw": raw, "options": {"raw": {"language": "json"}}}
    return {"name": f"{author} - {name}", "request": req,
            "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": test}}]}


def write_collection(key, title, items, variables=(), author="Ali Naji", description=None):
    Path("postman").mkdir(exist_ok=True)
    content = {"info": {"name": f"{author} - {title}", "schema": SCHEMA,
                        "description": description or "Run requests in order using AliNaji.environment.local.json. Each run creates its own records. Tokens come from the team's identity service; local CLI tokens only test authorization."},
               "variable": [{"key": v, "value": ""} for v in variables], "item": items}
    path = Path(f"postman/{author.replace(' ', '')}.{key}.postman_collection.json")
    path.write_text(json.dumps(content, indent=2), encoding="utf-8")
    return path


def threats():
    url = "{{threats_base}}/AliNaji/threats"
    body = {"threat_type": "Other Indicators", "threat_value": "postman-{{run_id}}", "description": "Lab attack indicator; High severity selected for investigation priority", "severity": "High", "source": "Postman lab run"}
    items = [
        request("Create attack indicator", "POST", url, 201, body, save="threat_id"),
        request("Reject duplicate indicator", "POST", url, 409, body),
        request("Create domain indicator", "POST", url, 201, {**body, "threat_type": "Domain", "threat_value": "lab-{{run_id}}.example.com", "severity": "Critical"}, save="domain_id"),
        request("Retrieve all threats", "GET", url, checks=["pm.test('Records array', () => pm.expect(pm.response.json()).to.be.an('array'));" ]),
        request("Retrieve specific threat", "GET", url + "/{{threat_id}}"),
        request("Search by type", "GET", url + "/search?threat_type=Domain"),
        request("Search by indicator", "GET", url + "/search?threat_value=postman-{{run_id}}"),
        request("Search by severity and source", "GET", url + "/search?severity=High&source=Postman%20lab%20run"),
        request("Search with no matches", "GET", url + "/search?source=absent-{{run_id}}", checks=["pm.test('Empty results', () => pm.expect(pm.response.json()).to.eql([]));"]),
        request("Analyst reads threat", "GET", url + "/{{threat_id}}", token="analyst_token"),
        request("Auditor reads threat", "GET", url + "/{{threat_id}}", token="auditor_token"),
        request("Auditor search forbidden by service matrix", "GET", url + "/search", 403, token="auditor_token"),
        request("Update threat severity", "PUT", url + "/{{threat_id}}", body={"description": "Confirmed lab indicator after review", "severity": "Critical", "source": "Postman lab run"}),
        request("Retrieve updated threat", "GET", url + "/{{threat_id}}", checks=["pm.test('Severity changed', () => pm.expect(pm.response.json().severity).to.eql('Critical'));" ]),
        request("Reject analyst update", "PUT", url + "/{{threat_id}}", 403, {"severity": "Low"}, token="analyst_token"),
        request("Reject analyst deletion", "DELETE", url + "/{{threat_id}}", 403, token="analyst_token"),
        request("Reject regular user read", "GET", url, 403, token="user_token"),
        request("Reject unauthenticated read", "GET", url, 401, token=None),
        request("Reject invalid IP", "POST", url, 422, {**body, "threat_type": "IP Address", "threat_value": "999.1.1.1"}),
        request("Reject invalid domain", "POST", url, 422, {**body, "threat_type": "Domain", "threat_value": "https://example.com"}),
        request("Reject invalid hash", "POST", url, 422, {**body, "threat_type": "File Hash", "threat_value": "not-a-hash"}),
        request("Reject invalid severity", "POST", url, 422, {**body, "severity": "Severe"}),
        request("Reject missing fields", "POST", url, 422, {}),
        request("Reject empty update", "PUT", url + "/{{threat_id}}", 422, {}),
        request("Missing threat", "GET", url + "/2147483647", 404),
        request("Delete threat", "DELETE", url + "/{{threat_id}}", 204),
        request("Verify deleted threat", "GET", url + "/{{threat_id}}", 404),
        request("Delete domain indicator", "DELETE", url + "/{{domain_id}}", 204),
    ]
    write_collection("threats", "Threat Intelligence", items, ("threat_id", "domain_id", "run_id"))
    path = Path("postman/AliNaji.threats.postman_collection.json")
    content = json.loads(path.read_text())
    content["event"] = [{"listen": "prerequest", "script": {"type": "text/javascript", "exec": [
        "if (pm.info.requestName === 'Ali Naji - Create attack indicator') pm.collectionVariables.set('run_id', pm.variables.replaceIn('{{$guid}}'));"
    ]}}]
    path.write_text(json.dumps(content, indent=2), encoding="utf-8")


def environment():
    path = Path("postman/AliNaji.environment.json")
    if path.exists():
        return
    values = {"threats_base": "http://127.0.0.1:8004", "vulnerabilities_base": "http://127.0.0.1:8007",
              "reports_base": "http://127.0.0.1:8006", "asset_id": "1", "admin_token": "",
              "analyst_token": "", "auditor_token": "", "user_token": ""}
    path.write_text(json.dumps({"name": "Ali Naji - Local Sprint 1", "values": [
        {"key": k, "value": v, "enabled": True, "type": "secret" if k.endswith("token") else "default"}
        for k, v in values.items()], "_postman_variable_scope": "environment"}, indent=2), encoding="utf-8")


def vulnerabilities():
    url = "{{vulnerabilities_base}}/AliNaji/vulnerabilities"
    body = {"title": "Lab vulnerability", "description": "Lab scanner finding requiring remediation",
            "cve_identifier": "CVE-2025-12345", "cvss_score": 8.1, "severity": "High",
            "affected_asset_id": "{{asset_id}}", "discovery_source": "Lab scanner"}
    path = url + "/{{vulnerability_id}}"
    items = [
        request("Create vulnerability on verified asset", "POST", url, 201, body, save="vulnerability_id",
                description="Requires ASSET_DETAIL_URL pointing to the teammate's real Assets service and asset_id identifying an existing asset. Starts Open with null resolution_date. CVSS is a numeric value from 0 to 10; severity is explicitly assessed."),
        request("Create critical vulnerability", "POST", url, 201, {**body, "title": "Critical lab finding", "severity": "Critical", "cvss_score": 9.8}, save="critical_id"),
        request("Retrieve all vulnerabilities", "GET", url),
        request("Retrieve specific vulnerability", "GET", path),
        request("Search vulnerabilities by CVE", "GET", url + "/search?cve_identifier=CVE-2025-12345"),
        request("Search vulnerabilities by severity", "GET", url + "/search?severity=High"),
        request("Search vulnerabilities by asset and status", "GET", url + "/search?affected_asset_id={{asset_id}}&status=Open"),
        request("Search vulnerabilities with no matches", "GET", url + "/search?cve_identifier=CVE-1900-99999", checks=["pm.test('Empty results', () => pm.expect(pm.response.json()).to.eql([]));"]),
        request("Auditor reads vulnerability", "GET", path, token="auditor_token"),
        request("Analyst updates vulnerability details", "PUT", path, body={"description": "Finding confirmed after investigation", "severity": "Critical", "cvss_score": 9.1}, token="analyst_token"),
        request("Reject skipped lifecycle step", "PUT", path, 409, {"status": "Closed"}),
        request("Begin vulnerability investigation", "PUT", path, body={"status": "Under Investigation"}, token="analyst_token"),
        request("Begin remediation", "PUT", path, body={"status": "In Progress"}, token="analyst_token"),
        request("Resolve vulnerability", "PUT", path, body={"status": "Resolved"}, token="analyst_token",
                checks=["pm.test('Resolution timestamp recorded', () => pm.expect(pm.response.json().resolution_date).to.be.a('string'));" ]),
        request("Close vulnerability", "PUT", path, body={"status": "Closed"}, token="analyst_token"),
        request("Reject backward lifecycle transition", "PUT", path, 409, {"status": "Open"}),
        request("Reject analyst vulnerability creation", "POST", url, 403, body, token="analyst_token"),
        request("Reject auditor update", "PUT", path, 403, {"severity": "Low"}, token="auditor_token"),
        request("Reject analyst vulnerability deletion", "DELETE", path, 403, token="analyst_token"),
        request("Reject employee vulnerability access", "GET", url, 403, token="user_token"),
        request("Reject unauthenticated vulnerability access", "GET", url, 401, token=None),
        request("Reject invalid CVE", "POST", url, 422, {**body, "cve_identifier": "invalid"}),
        request("Reject invalid CVSS", "POST", url, 422, {**body, "cvss_score": 10.1}),
        request("Reject invalid asset id", "POST", url, 422, {**body, "affected_asset_id": 0}),
        request("Reject invalid vulnerability severity", "POST", url, 422, {**body, "severity": "Severe"}),
        request("Reject missing vulnerability fields", "POST", url, 422, {}),
        request("Reject empty vulnerability update", "PUT", path, 422, {}),
        request("Retrieve missing vulnerability", "GET", url + "/2147483647", 404),
        request("Delete vulnerability", "DELETE", path, 204),
        request("Verify deleted vulnerability", "GET", path, 404),
        request("Delete critical vulnerability", "DELETE", url + "/{{critical_id}}", 204),
    ]
    write_collection("vulnerabilities", "Vulnerability Management", items, ("vulnerability_id", "critical_id"))


def reports():
    url = "{{reports_base}}/AliNaji/reports"
    owned = [
        request("Read threat report source", "GET", "{{threats_base}}/AliNaji/threats", checks=[
            "pm.collectionVariables.set('expected_threats', JSON.stringify(pm.response.json()));"]),
        request("Generate threat report", "GET", url + "/threats", checks=[
            "const r = pm.response.json(); const source = JSON.parse(pm.collectionVariables.get('expected_threats'));",
            "pm.test('Total matches Threat Intelligence API', () => pm.expect(r.total_threats).to.eql(source.length));",
            "pm.test('Severity totals reconcile', () => pm.expect(Object.values(r.threats_by_severity).reduce((a,b)=>a+b,0)).to.eql(r.total_threats));",
            "pm.test('Type totals reconcile', () => pm.expect(Object.values(r.threats_by_type).reduce((a,b)=>a+b,0)).to.eql(r.total_threats));",
            "pm.test('Recent threats capped at ten', () => pm.expect(r.recent_added_threats.length).to.be.at.most(10));"]),
        request("Read vulnerability report source", "GET", "{{vulnerabilities_base}}/AliNaji/vulnerabilities", checks=[
            "pm.collectionVariables.set('expected_vulnerabilities', JSON.stringify(pm.response.json()));"]),
        request("Generate vulnerability report", "GET", url + "/vulnerabilities", checks=[
            "const r = pm.response.json(); const source = JSON.parse(pm.collectionVariables.get('expected_vulnerabilities'));",
            "pm.test('Total matches Vulnerability Management API', () => pm.expect(r.total_vulnerabilities).to.eql(source.length));",
            "pm.test('Severity totals reconcile', () => pm.expect(Object.values(r.vulnerabilities_by_severity).reduce((a,b)=>a+b,0)).to.eql(r.total_vulnerabilities));",
            "pm.test('Status totals reconcile', () => pm.expect(Object.values(r.vulnerabilities_by_status).reduce((a,b)=>a+b,0)).to.eql(r.total_vulnerabilities));",
            "pm.test('Critical count matches source', () => pm.expect(r.critical_vulnerabilities).to.eql(source.filter(v=>v.severity==='Critical').length));"]),
        request("Auditor generates threat report", "GET", url + "/threats", token="auditor_token"),
    ]
    dependent = []
    for kind, total, grouped in [("incidents", "total_incidents", "incidents_by_severity"),
                                  ("assets", "total_assets", "assets_by_type")]:
        dependent.append(request(f"Generate {kind} report", "GET", url + "/" + kind, checks=[
            f"const r=pm.response.json(); pm.test('Grouped counts reconcile', () => pm.expect(Object.values(r.{grouped}).reduce((a,b)=>a+b,0)).to.eql(r.{total}));"]))
    dependent.extend([
        request("Generate security summary report", "GET", url + "/summary", checks=[
            "const r=pm.response.json(); pm.test('All six sources used', () => pm.expect(r.sources.length).to.eql(6));",
            "pm.test('Open incident count valid', () => pm.expect(r.open_incidents).to.be.at.most(r.incidents));"]),
        request("Generate activity report", "GET", url + "/activity", checks=[
            "const r=pm.response.json(); pm.test('Login counters consistent', () => pm.expect(r.failed_login_attempts).to.be.at.most(r.login_attempts));"]),
    ])
    for kind in ["summary", "incidents", "assets", "vulnerabilities", "activity"]:
        dependent.append(request(f"Auditor generates {kind} report", "GET", url + "/" + kind, token="auditor_token"))
    security = []
    for kind in ["summary", "incidents", "assets", "threats", "vulnerabilities", "activity"]:
        security.extend([
            request(f"Reject analyst {kind} report", "GET", url + "/" + kind, 403, token="analyst_token"),
            request(f"Reject employee {kind} report", "GET", url + "/" + kind, 403, token="user_token"),
        ])
    security.append(request("Reject unauthenticated report", "GET", url + "/summary", 401, token=None))
    write_collection("reports", "Security Reports", [
        {"name": "Available own services", "item": owned},
        {"name": "Team dependent reports", "item": dependent},
        {"name": "Access control", "item": security},
    ], ("expected_threats", "expected_vulnerabilities"))


KASSEM = "Mohamed Kassem"
KASSEM_ORDER = "Run the Mohamed Kassem collections in order: Users first (it logs in and stores tokens and user ids in the environment), then Logs, then Notifications. Use MohamedKassem.environment.json and fill admin_password locally."
NO_PASSWORD = "pm.test('No password data returned', () => pm.expect(pm.response.text()).not.to.include('password'));"
EMPTY = "pm.test('Empty results', () => pm.expect(pm.response.json()).to.eql([]));"


def kassem(name, method, url, status=200, body=None, token="admin_token", checks=(), save=None, description=""):
    if description:
        description = f"{description} Expected HTTP {status}. Author: {KASSEM}."
    return request(name, method, url, status, body, token, checks, save, description, KASSEM,
                   "docs/users-logs-notifications.md")


def keep(key, expression):
    return f"if (pm.response.code < 300) pm.environment.set('{key}', {expression});"


def every(field, expected):
    return (f"pm.test('Every record matches the {field} filter', () => pm.response.json().forEach("
            f"r => pm.expect(String(r.{field})).to.eql(String({expected}))));")


def with_header(item, key, value):
    item["request"]["header"].append({"key": key, "value": value})
    return item


def kassem_collection(key, title, items, variables, first_request):
    path = write_collection(key, title, items, variables, KASSEM, KASSEM_ORDER)
    content = json.loads(path.read_text())
    content["event"] = [{"listen": "prerequest", "script": {"type": "text/javascript", "exec": [
        f"if (pm.info.requestName === '{KASSEM} - {first_request}') {{",
        "  pm.collectionVariables.set('run_id', Math.random().toString(36).slice(2, 8));",
        "  pm.collectionVariables.set('today', new Date().toISOString().slice(0, 10));",
        "}"]}}]
    path.write_text(json.dumps(content, indent=2), encoding="utf-8")


def users():
    url = "{{users_base}}/MohamedKassem/users"

    def account(name, role):
        return {"full_name": f"Lab {name.title()}", "username": name + "_{{run_id}}",
                "email": name + "_{{run_id}}@example.com", "password": "{{test_password}}",
                "department": "Security Operations", "role": role}

    analyst, auditor = account("analyst", "Security Analyst"), account("auditor", "Auditor")
    employee, second = account("employee", "Regular Employee/User"), account("second", "Regular Employee/User")
    token = "pm.response.json().access_token"
    items = [
        kassem("Login administrator", "POST", url + "/login", body={"username": "{{admin_username}}", "password": "{{admin_password}}"},
               token=None, checks=[keep("admin_token", token), keep("admin_id", "pm.response.json().user.id"),
                                   "pm.test('Bearer token issued', () => pm.expect(pm.response.json().token_type).to.eql('bearer'));"],
               description="Verifies the administrator's username and password against the stored bcrypt hash and returns a signed JWT, saved as admin_token. The first administrator is created with scripts.create_admin."),
        kassem("Register security analyst", "POST", url + "/register", 201, analyst,
               checks=[keep("analyst_id", "pm.response.json().id"), keep("analyst_username", "pm.response.json().username"), NO_PASSWORD],
               description="An administrator registers a privileged account. The password is hashed before it is stored and is never returned."),
        kassem("Register auditor", "POST", url + "/register", 201, auditor,
               checks=[keep("auditor_id", "pm.response.json().id"), keep("auditor_username", "pm.response.json().username")]),
        kassem("Self-register regular employee", "POST", url + "/register", 201, employee, token=None,
               checks=[keep("user_id", "pm.response.json().id"), keep("user_username", "pm.response.json().username"), NO_PASSWORD],
               description="Public self-registration. Without an administrator token only the Regular Employee/User role is allowed."),
        kassem("Self-register second employee", "POST", url + "/register", 201, second, token=None, save="other_id",
               checks=["if (pm.response.code === 201) pm.collectionVariables.set('other_username', pm.response.json().username);"]),
        kassem("Login analyst with username", "POST", url + "/login", body={"username": analyst["username"], "password": "{{test_password}}"},
               token=None, checks=[keep("analyst_token", token)]),
        kassem("Login auditor with email", "POST", url + "/login", body={"email": auditor["email"], "password": "{{test_password}}"},
               token=None, checks=[keep("auditor_token", token)], description="Login accepts either the username or the email."),
        kassem("Login regular employee", "POST", url + "/login", body={"username": employee["username"], "password": "{{test_password}}"},
               token=None, checks=[keep("user_token", token)]),
        kassem("Reject wrong password", "POST", url + "/login", 401, {"username": employee["username"], "password": "Wrong#Pass1"},
               token=None, description="Failed authentication. Recorded as a LOGIN_FAILED audit event."),
        kassem("Reject unknown username", "POST", url + "/login", 401, {"username": "nobody_{{run_id}}", "password": "Wrong#Pass1"}, token=None),
        kassem("Reject login without username or email", "POST", url + "/login", 422, {"password": "{{test_password}}"}, token=None),
        kassem("Reject duplicate username", "POST", url + "/register", 409, {**employee, "email": "copy_{{run_id}}@example.com"}, token=None,
               checks=["pm.test('Duplicate username message', () => pm.expect(pm.response.json().message).to.eql('Username already exists'));"],
               description="Usernames are unique without regard to case, enforced by a UNIQUE constraint in the users table."),
        kassem("Reject duplicate email", "POST", url + "/register", 409, {**employee, "username": "copy_{{run_id}}"}, token=None),
        kassem("Reject invalid email", "POST", url + "/register", 422, {**employee, "username": "bad_{{run_id}}", "email": "not-an-email"}, token=None),
        kassem("Reject weak password", "POST", url + "/register", 422, {**employee, "username": "weak_{{run_id}}", "email": "weak_{{run_id}}@example.com", "password": "password"},
               token=None, description="Passwords need at least 8 characters with an uppercase letter, a lowercase letter, a digit and a symbol."),
        kassem("Reject missing registration fields", "POST", url + "/register", 422, {}, token=None),
        kassem("Reject invalid role", "POST", url + "/register", 422, {**employee, "username": "role_{{run_id}}", "role": "Admin"}, token=None),
        kassem("Reject anonymous administrator registration", "POST", url + "/register", 403,
               {**account("intruder", "Security Administrator")}, token=None),
        kassem("Reject analyst registering users", "POST", url + "/register", 403, account("blocked", "Regular Employee/User"), token="analyst_token"),
        kassem("Retrieve all users", "GET", url, checks=["pm.test('Records array', () => pm.expect(pm.response.json()).to.be.an('array'));", NO_PASSWORD]),
        kassem("Auditor retrieves all users", "GET", url, token="auditor_token"),
        kassem("Reject analyst listing users", "GET", url, 403, token="analyst_token"),
        kassem("Reject employee listing users", "GET", url, 403, token="user_token"),
        kassem("Reject unauthenticated listing", "GET", url, 401, token=None),
        kassem("Retrieve user by username", "GET", url + "/{{user_username}}", checks=[NO_PASSWORD]),
        kassem("Retrieve non-existing username", "GET", url + "/missing_{{run_id}}", 404),
        kassem("Employee retrieves own profile", "GET", url + "/{{user_username}}", token="user_token"),
        kassem("Reject employee reading another profile", "GET", url + "/{{analyst_username}}", 403, token="user_token"),
        kassem("Employee updates own information", "PUT", url + "/{{user_id}}", body={"full_name": "Lab Employee Updated", "email": "updated_{{run_id}}@example.com", "department": "Finance"},
               token="user_token", checks=["pm.test('Department updated', () => pm.expect(pm.response.json().department).to.eql('Finance'));"],
               description="Users may update their own full_name, email and department."),
        kassem("Reject employee updating another user", "PUT", url + "/{{other_id}}", 403, {"department": "Finance"}, token="user_token"),
        kassem("Reject employee changing own role", "PUT", url + "/{{user_id}}", 403, {"role": "Security Administrator"}, token="user_token"),
        kassem("Reject empty update", "PUT", url + "/{{user_id}}", 422, {}),
        kassem("Reject non-updatable field", "PUT", url + "/{{user_id}}", 422, {"username": "renamed_{{run_id}}"}),
        kassem("Update non-existing user", "PUT", url + "/2147483647", 404, {"department": "Finance"}),
        kassem("Administrator changes user role", "PUT", url + "/{{other_id}}", body={"role": "Security Analyst"},
               checks=["pm.test('Role changed', () => pm.expect(pm.response.json().role).to.eql('Security Analyst'));"],
               description="Role assignment is administrator only. Recorded as ROLE_CHANGED and the user receives a System Notification."),
        kassem("Administrator suspends account", "PUT", url + "/{{other_id}}", body={"account_status": "Suspended"}),
        kassem("Reject suspended account login", "POST", url + "/login", 403, {"username": "{{other_username}}", "password": "{{test_password}}"},
               token=None, description="Inactive and suspended accounts cannot authenticate even with the correct password."),
        kassem("Reject analyst deleting user", "DELETE", url + "/{{other_id}}", 403, token="analyst_token",
               description="Only Security Administrator tokens pass the role check; the denial is recorded as PERMISSION_DENIED."),
        kassem("Reject auditor deleting user", "DELETE", url + "/{{other_id}}", 403, token="auditor_token"),
        kassem("Delete user", "DELETE", url + "/{{other_id}}", 204),
        kassem("Verify deleted user", "GET", url + "/{{other_username}}", 404),
    ]
    kassem_collection("users", "Users and Identity Management", items, ("run_id", "today", "other_id", "other_username"),
                      "Login administrator")


def logs():
    url = "{{logs_base}}/MohamedKassem/logs"
    path = url + "/{{log_id}}"
    entry = {"user_id": "{{user_id}}", "action": "MANUAL_REVIEW", "description": "Administrator reviewed the employee's access request",
             "severity": "Information", "related_service": "Security Audit Logging"}
    export = {**entry, "action": "EXPORT_REQUESTED", "description": "Employee requested a data export"}
    items = [
        kassem("Create log record", "POST", url, 201, entry, save="log_id",
               description="Administrator or service token. Users, Notifications, Threats, Vulnerabilities and Reports deliver their events here automatically."),
        kassem("Create warning log for analyst", "POST", url, 201,
               {**entry, "user_id": "{{analyst_id}}", "action": "SUSPICIOUS_ACTIVITY", "description": "Repeated access to restricted files", "severity": "Warning", "related_service": "Incident Management"}),
        kassem("Create critical log with unknown actor", "POST", url, 201,
               {**entry, "user_id": None, "action": "MALWARE_DETECTED", "description": "Endpoint agent reported malware", "severity": "Critical", "related_service": "Threat Intelligence"},
               description="user_id is null when no authenticated actor exists."),
        with_header(kassem("Create log with idempotency key", "POST", url, 201, export, save="idempotent_id"), "Idempotency-Key", "postman-{{run_id}}"),
        with_header(kassem("Replay same idempotency key", "POST", url, 200, export, checks=[
            "pm.test('Stored record returned once', () => pm.expect(Number(pm.response.json().id)).to.eql(Number(pm.collectionVariables.get('idempotent_id'))));"],
            description="A retried delivery with the same Idempotency-Key returns the stored record instead of a duplicate."), "Idempotency-Key", "postman-{{run_id}}"),
        kassem("Reject invalid log severity", "POST", url, 422, {**entry, "severity": "Severe"}),
        kassem("Reject missing log fields", "POST", url, 422, {}),
        kassem("Reject timestamp without timezone", "POST", url, 422, {**entry, "timestamp": "2026-10-01T08:30:00"}),
        kassem("Reject analyst creating log", "POST", url, 403, entry, token="analyst_token"),
        kassem("Reject auditor creating log", "POST", url, 403, entry, token="auditor_token"),
        kassem("Retrieve all logs", "GET", url, checks=["pm.test('Records array', () => pm.expect(pm.response.json()).to.be.an('array'));"]),
        kassem("Auditor retrieves all logs", "GET", url, token="auditor_token"),
        kassem("Reject analyst listing all logs", "GET", url, 403, token="analyst_token"),
        kassem("Reject employee listing logs", "GET", url, 403, token="user_token"),
        kassem("Reject unauthenticated log access", "GET", url, 401, token=None),
        kassem("Retrieve specific log", "GET", path),
        kassem("Analyst retrieves specific log", "GET", path, token="analyst_token"),
        kassem("Retrieve missing log", "GET", url + "/2147483647", 404),
        kassem("Search logs by user", "GET", url + "/search?user_id={{user_id}}", checks=[every("user_id", "pm.environment.get('user_id')")]),
        kassem("Search logs by action", "GET", url + "/search?action=LOGIN_SUCCESS", checks=[every("action", "'LOGIN_SUCCESS'")]),
        kassem("Search logs by severity", "GET", url + "/search?severity=Warning", checks=[every("severity", "'Warning'")]),
        kassem("Search logs by related service", "GET", url + "/search?related_service=Users%20and%20Identity%20Management",
               checks=[every("related_service", "'Users and Identity Management'")]),
        kassem("Search logs by date", "GET", url + "/search?date={{today}}",
               checks=["pm.test('Same UTC day', () => pm.response.json().forEach(r => pm.expect(r.timestamp.slice(0, 10)).to.eql(pm.collectionVariables.get('today'))));"],
               description="date is a UTC calendar day in YYYY-MM-DD format; all filters combine with AND."),
        kassem("Search logs with combined filters", "GET", url + "/search?user_id={{analyst_id}}&severity=Warning",
               checks=["pm.test('At least one match', () => pm.expect(pm.response.json().length).to.be.above(0));"]),
        kassem("Search logs with no matches", "GET", url + "/search?action=ABSENT_{{run_id}}", checks=[EMPTY]),
        kassem("Auditor searches logs", "GET", url + "/search?severity=Warning", token="auditor_token"),
        kassem("Analyst searches logs", "GET", url + "/search?severity=Warning", token="analyst_token"),
        kassem("Reject employee searching logs", "GET", url + "/search", 403, token="user_token"),
        kassem("Reject invalid search value", "GET", url + "/search?severity=Severe", 422),
        kassem("Retrieve logs by user", "GET", url + "/user/{{user_id}}",
               checks=["pm.test('User has activity', () => pm.expect(pm.response.json().length).to.be.above(0));", every("user_id", "pm.environment.get('user_id')")]),
        kassem("Auditor retrieves logs by user", "GET", url + "/user/{{user_id}}", token="auditor_token"),
        kassem("Retrieve logs for user without activity", "GET", url + "/user/no-activity-{{run_id}}", checks=[EMPTY],
               description="A user with no recorded activity returns HTTP 200 with an empty array."),
        kassem("Reject analyst retrieving logs by user", "GET", url + "/user/{{user_id}}", 403, token="analyst_token"),
        kassem("Reject analyst deleting log", "DELETE", path, 403, token="analyst_token"),
        kassem("Reject employee deleting log", "DELETE", path, 403, token="user_token"),
        kassem("Delete log", "DELETE", path, 204, description="Only administrators can delete logs. The deletion itself is recorded as a LOG_DELETED event."),
        kassem("Verify deleted log", "GET", path, 404),
        kassem("Verify deletion was audited", "GET", url + "/search?action=LOG_DELETED&date={{today}}",
               checks=["pm.test('LOG_DELETED recorded', () => pm.expect(pm.response.json().length).to.be.above(0));"]),
    ]
    kassem_collection("logs", "Security Audit Logging", items, ("run_id", "today", "log_id", "idempotent_id"), "Create log record")


def notifications():
    url = "{{notifications_base}}/MohamedKassem/notifications"
    path = url + "/{{notification_id}}"
    alert = {"user_id": "{{user_id}}", "title": "Suspicious login detected", "message": "A login to your account from a new location was blocked.",
             "notification_type": "Security Alert", "severity": "High"}
    items = [
        kassem("Create security alert for employee", "POST", url, 201, alert, save="notification_id",
               description="Administrator or service token. The recipient is verified through the Users service before the notification is stored as Unread."),
        kassem("Create incident assignment for analyst", "POST", url, 201,
               {**alert, "user_id": "{{analyst_id}}", "title": "Incident assigned", "message": "You were assigned a phishing incident.", "notification_type": "Incident Assignment", "severity": "Medium"}),
        kassem("Create system notification for employee", "POST", url, 201,
               {**alert, "title": "Scheduled maintenance", "message": "The VPN will be unavailable tonight.", "notification_type": "System Notification", "severity": "Low"},
               save="system_notification_id"),
        kassem("Reject unknown recipient", "POST", url, 404, {**alert, "user_id": 2147483647}),
        kassem("Reject invalid notification type", "POST", url, 422, {**alert, "notification_type": "Alert"}),
        kassem("Reject invalid notification severity", "POST", url, 422, {**alert, "severity": "Severe"}),
        kassem("Reject missing notification fields", "POST", url, 422, {}),
        kassem("Reject analyst creating notification", "POST", url, 403, alert, token="analyst_token"),
        kassem("Reject auditor creating notification", "POST", url, 403, alert, token="auditor_token"),
        kassem("Reject employee creating notification", "POST", url, 403, alert, token="user_token"),
        kassem("Employee retrieves own notifications", "GET", url + "/user/{{user_id}}", token="user_token",
               checks=["pm.test('Two notifications', () => pm.expect(pm.response.json().length).to.be.at.least(2));", every("user_id", "pm.environment.get('user_id')")]),
        kassem("Administrator retrieves user notifications", "GET", url + "/user/{{user_id}}"),
        kassem("Auditor retrieves user notifications", "GET", url + "/user/{{user_id}}", token="auditor_token"),
        kassem("Analyst retrieves own notifications", "GET", url + "/user/{{analyst_id}}", token="analyst_token"),
        kassem("Retrieve empty notification results", "GET", url + "/user/{{auditor_id}}", checks=[EMPTY],
               description="A user without notifications returns HTTP 200 with an empty array."),
        kassem("Reject employee reading another user's notifications", "GET", url + "/user/{{analyst_id}}", 403, token="user_token",
               description="Employees and analysts can only read notifications addressed to them."),
        kassem("Retrieve specific notification", "GET", path, token="user_token"),
        kassem("Auditor retrieves specific notification", "GET", path, token="auditor_token"),
        kassem("Retrieve missing notification", "GET", url + "/2147483647", 404),
        kassem("Reject analyst reading employee notification", "GET", path, 403, token="analyst_token"),
        kassem("Mark notification as read", "PUT", path + "/read", token="user_token",
               checks=["const n = pm.response.json(); pm.test('Status Read with read date', () => { pm.expect(n.status).to.eql('Read'); pm.expect(n.read_date).to.be.a('string'); });",
                       "pm.collectionVariables.set('read_date', n.read_date);"],
               description="Moves the notification from Unread to Read and records read_date."),
        kassem("Mark notification as read again", "PUT", path + "/read", token="user_token",
               checks=["pm.test('Original read date kept', () => pm.expect(pm.response.json().read_date).to.eql(pm.collectionVariables.get('read_date')));"],
               description="Repeating the call is safe and keeps the original read_date."),
        kassem("Reject auditor marking as read", "PUT", path + "/read", 403, token="auditor_token"),
        kassem("Reject analyst marking employee notification", "PUT", path + "/read", 403, token="analyst_token"),
        kassem("Search notifications by user", "GET", url + "/search?user_id={{user_id}}", checks=[every("user_id", "pm.environment.get('user_id')")]),
        kassem("Search notifications by type", "GET", url + "/search?notification_type=Incident%20Assignment",
               checks=[every("notification_type", "'Incident Assignment'")]),
        kassem("Search notifications by severity", "GET", url + "/search?severity=High", checks=[every("severity", "'High'")]),
        kassem("Search notifications by status", "GET", url + "/search?status=Unread", checks=[every("status", "'Unread'")]),
        kassem("Search notifications with combined filters", "GET", url + "/search?user_id={{user_id}}&status=Read",
               checks=["pm.test('Read notification found', () => pm.expect(pm.response.json().map(n => n.id)).to.include(Number(pm.collectionVariables.get('notification_id'))));"]),
        kassem("Search notifications with no matches", "GET", url + "/search?user_id={{auditor_id}}", checks=[EMPTY]),
        kassem("Analyst searches own notifications", "GET", url + "/search", token="analyst_token",
               checks=[every("user_id", "pm.environment.get('analyst_id')")], description="Analyst searches are limited to the analyst's own notifications."),
        kassem("Reject analyst searching another user", "GET", url + "/search?user_id={{user_id}}", 403, token="analyst_token"),
        kassem("Reject employee searching notifications", "GET", url + "/search", 403, token="user_token"),
        kassem("Reject invalid notification search", "GET", url + "/search?status=Seen", 422),
        kassem("Reject unauthenticated notification access", "GET", url + "/user/{{user_id}}", 401, token=None),
        kassem("Reject analyst deleting notification", "DELETE", url + "/{{system_notification_id}}", 403, token="analyst_token"),
        kassem("Reject employee deleting notification", "DELETE", url + "/{{system_notification_id}}", 403, token="user_token"),
        kassem("Delete notification", "DELETE", url + "/{{system_notification_id}}", 204),
        kassem("Verify deleted notification", "GET", url + "/{{system_notification_id}}", 404),
    ]
    kassem_collection("notifications", "Notification and Alert Management", items,
                      ("run_id", "today", "notification_id", "system_notification_id", "read_date"), "Create security alert for employee")


def kassem_environment():
    path = Path("postman/MohamedKassem.environment.json")
    if path.exists():
        return
    values = {"users_base": "http://127.0.0.1:8001", "logs_base": "http://127.0.0.1:8005",
              "notifications_base": "http://127.0.0.1:8008", "admin_username": "admin1", "admin_password": "",
              "test_password": "Lab#Pass2026", "admin_token": "", "analyst_token": "", "auditor_token": "",
              "user_token": "", "admin_id": "", "analyst_id": "", "auditor_id": "", "user_id": "",
              "analyst_username": "", "auditor_username": "", "user_username": ""}
    path.write_text(json.dumps({"name": "Mohamed Kassem - Local Sprint 1", "values": [
        {"key": k, "value": v, "enabled": True, "type": "secret" if k.endswith(("token", "password")) else "default"}
        for k, v in values.items()], "_postman_variable_scope": "environment"}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=["users", "logs", "notifications", "threats", "vulnerabilities", "reports"])
    args = parser.parse_args()
    globals()[args.service]()
    (kassem_environment if args.service in ("users", "logs", "notifications") else environment)()
