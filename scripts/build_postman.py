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
        req["body"] = {"mode": "raw", "raw": json.dumps(body, indent=2), "options": {"raw": {"language": "json"}}}
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=["threats"])
    args = parser.parse_args()
    globals()[args.service]()
    environment()
