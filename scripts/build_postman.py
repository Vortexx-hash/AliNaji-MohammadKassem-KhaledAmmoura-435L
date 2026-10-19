"""Generate version 2.1 collections; no tokens or invented execution evidence."""
import argparse
import json
from pathlib import Path

SCHEMA = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"


def request(name, method, url, status=200, body=None, token="admin_token", checks=(), save=None, description=""):
    test = [f"pm.test('HTTP {status}', () => pm.response.to.have.status({status}));"]
    test.extend(checks)
    if save:
        test.append(f"if (pm.response.code === {status}) pm.collectionVariables.set('{save}', pm.response.json().id);")
    req = {"method": method, "header": [], "url": url,
           "description": description or f"{name} (Ali Naji). Expected HTTP {status}. See docs/api.md for fields and errors.",
           "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{" + (token or "") + "}}", "type": "string"}]}}
    if token is None:
        req["auth"] = {"type": "noauth"}
    if body is not None:
        req["header"] = [{"key": "Content-Type", "value": "application/json"}]
        raw = json.dumps(body, indent=2).replace('"{{asset_id}}"', '{{asset_id}}')
        req["body"] = {"mode": "raw", "raw": raw, "options": {"raw": {"language": "json"}}}
    return {"name": f"Ali Naji - {name}", "request": req,
            "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": test}}]}


def write_collection(key, title, items, variables=()):
    Path("postman").mkdir(exist_ok=True)
    content = {"info": {"name": f"Ali Naji - {title}", "schema": SCHEMA,
                        "description": "Run requests in order using AliNaji.environment.local.json. Each run creates its own records. Tokens come from the team's identity service; local CLI tokens only test authorization."},
               "variable": [{"key": v, "value": ""} for v in variables], "item": items}
    Path(f"postman/AliNaji.{key}.postman_collection.json").write_text(json.dumps(content, indent=2), encoding="utf-8")


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=["threats", "vulnerabilities", "reports"])
    args = parser.parse_args()
    globals()[args.service]()
    environment()
