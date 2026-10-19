"""Start isolated real services backed by explicitly synthetic missing-dependency fixtures."""
import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import httpx

from demo.runner import PORTS
from scripts.dev_tokens import issue
from shared.auth import Role
from shared.config import Settings

ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = ROOT / "data" / "demo"
ENVIRONMENT = ROOT / "postman" / "AliNaji.demo.environment.local.json"
FIXTURE_BASE = "http://127.0.0.1:8010/AliNaji/demo"


def settings():
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    key_path = DEMO_DIR / "jwt.key"
    if not key_path.exists():
        with key_path.open("x", encoding="ascii") as file:
            file.write(secrets.token_urlsafe(48))
    return Settings(jwt_secret=key_path.read_text(encoding="ascii"), data_dir=DEMO_DIR / "services",
                    jwt_issuer="security-lab-demo", jwt_audience="security-services-demo")


def write_environment(config):
    env = json.loads((ROOT / "postman" / "AliNaji.environment.json").read_text(encoding="utf-8"))
    env["name"] = "Ali Naji - DEMO with SYNTHETIC dependencies"
    values = {"threats_base": "http://127.0.0.1:8104", "vulnerabilities_base": "http://127.0.0.1:8107",
              "reports_base": "http://127.0.0.1:8106", "asset_id": "1"}
    for name, role in {"admin_token": Role.ADMIN, "analyst_token": Role.ANALYST,
                       "auditor_token": Role.AUDITOR, "user_token": Role.USER}.items():
        values[name] = issue(config, role.value, f"local-{name}", minutes=120)
    for entry in env["values"]:
        entry["value"] = values[entry["key"]]
    ENVIRONMENT.write_text(json.dumps(env, indent=2), encoding="utf-8")
    print(f"Postman environment: {ENVIRONMENT.relative_to(ROOT)} (tokens valid for 2 hours)", flush=True)


def child_environment(config):
    env = os.environ.copy()
    env.update({"JWT_SECRET": config.jwt_secret, "JWT_ISSUER": config.jwt_issuer,
                "JWT_AUDIENCE": config.jwt_audience, "DATA_DIR": str(config.data_dir),
                "IDENTITY_ME_URL": "", "ASSET_DETAIL_URL": FIXTURE_BASE + "/assets/{id}",
                "AUDIT_POST_URL": FIXTURE_BASE + "/logs",
                "AUDIT_SERVICE_TOKEN": issue(config, Role.ADMIN.value, "demo-audit-sender", minutes=1440),
                "THREATS_LIST_URL": "http://127.0.0.1:8104/AliNaji/threats",
                "VULNERABILITIES_LIST_URL": "http://127.0.0.1:8107/AliNaji/vulnerabilities",
                "USERS_LIST_URL": FIXTURE_BASE + "/users", "ASSETS_LIST_URL": FIXTURE_BASE + "/assets",
                "INCIDENTS_LIST_URL": FIXTURE_BASE + "/incidents", "LOGS_LIST_URL": FIXTURE_BASE + "/logs"})
    return env


def wait_ready(processes):
    deadline = time.monotonic() + 40
    pending = set(processes)
    with httpx.Client(timeout=1, trust_env=False) as client:
        while pending and time.monotonic() < deadline:
            for name in list(pending):
                if processes[name].poll() is not None:
                    raise RuntimeError(f"{name} exited; inspect data/demo/{name}.log")
                path = "/AliNaji/demo/health" if name == "dependencies" else "/AliNaji/health"
                try:
                    response = client.get(f"http://127.0.0.1:{PORTS[name]}{path}")
                    if response.status_code == 200 and response.headers.get("X-Lab-Mode") == "synthetic-dependencies":
                        pending.remove(name)
                except httpx.HTTPError:
                    pass
            if pending:
                time.sleep(0.2)
    if pending:
        raise RuntimeError("Demo startup timed out; inspect data/demo/*.log")


def seed(config):
    token = issue(config, Role.ADMIN.value, "local-admin_token", minutes=120)
    with httpx.Client(headers={"Authorization": "Bearer " + token}, timeout=10, trust_env=False) as client:
        url = "http://127.0.0.1:8104/AliNaji/threats"
        for kind, value, severity in [("IP Address", "203.0.113.8", "High"),
                                      ("Domain", "phishing.example.com", "Critical"),
                                      ("File Hash", "ab" * 32, "Medium"),
                                      ("Other Indicators", "DEMO-ATTACK-PATTERN", "Low")]:
            response = client.post(url, json={"threat_type": kind, "threat_value": value, "severity": severity,
                                              "description": "Synthetic lab sample created through the actual API",
                                              "source": "Demo fixture samples"})
            if response.status_code not in (201, 409):
                raise RuntimeError(f"Demo threat seed failed: HTTP {response.status_code}")
        url = "http://127.0.0.1:8107/AliNaji/vulnerabilities"
        response = client.get(url)
        response.raise_for_status()
        existing = {row["title"] for row in response.json() if row["discovery_source"] == "Demo fixture scanner"}
        states = ["Open", "Under Investigation", "In Progress", "Resolved", "Closed"]
        for index, (severity, score) in enumerate([("High", 8.1), ("Critical", 9.8), ("Medium", 5.5), ("Low", 2.1), ("Critical", 9.1)]):
            title = f"DEMO finding {index + 1}"
            if title in existing:
                continue
            response = client.post(url, json={"title": title, "description": "Synthetic finding on a demo fixture asset",
                "cve_identifier": f"CVE-2025-{12000 + index}", "cvss_score": score, "severity": severity,
                "affected_asset_id": index % 3 + 1, "discovery_source": "Demo fixture scanner"})
            response.raise_for_status()
            record_id = response.json()["id"]
            for state in states[1:index + 1]:
                response = client.put(f"{url}/{record_id}", json={"status": state})
                response.raise_for_status()
    print("Seeded through real APIs: 4 threat samples and 5 vulnerability samples covering every lifecycle status.", flush=True)


def terminate(processes):
    for process in reversed(list(processes.values())):
        if process.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def start(config):
    # Verify explicit demo ports before starting any child; never stop existing services.
    for port in PORTS.values():
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                raise RuntimeError(f"Demo port {port} is busy. Use 'python -m scripts.demo stop' if the demo is already running.")
    run_id = str(uuid4())
    state_path, stop_path = DEMO_DIR / "state.json", DEMO_DIR / "stop.request"
    stop_path.unlink(missing_ok=True)
    processes, files = {}, []
    try:
        for name in PORTS:
            log = (DEMO_DIR / f"{name}.log").open("a", encoding="utf-8")
            files.append(log)
            processes[name] = subprocess.Popen([sys.executable, "-m", "demo.runner", name, "--run-id", run_id],
                cwd=ROOT, env=child_environment(config), stdout=log, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        state_path.write_text(json.dumps({"run_id": run_id, "launcher_pid": os.getpid()}), encoding="utf-8")
        wait_ready(processes)
        write_environment(config)
        seed(config)
        print("DEMO READY. Missing dependencies use explicitly synthetic fixtures.", flush=True)
        for name in ("threats", "vulnerabilities", "reports"):
            print(f"{name}: http://127.0.0.1:{PORTS[name]}/AliNaji/docs", flush=True)
        print("Run all three existing Postman collections using the DEMO environment.\nStop: Ctrl+C or python -m scripts.demo stop", flush=True)
        while not stop_path.exists():
            for name, process in processes.items():
                if process.poll() is not None:
                    raise RuntimeError(f"{name} stopped unexpectedly; inspect data/demo/{name}.log")
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        terminate(processes)
        for file in files:
            file.close()
        state_path.unlink(missing_ok=True)
        stop_path.unlink(missing_ok=True)
        print("Demo stopped. Its separate databases are preserved for the next run.", flush=True)


def stop():
    state_path = DEMO_DIR / "state.json"
    if not state_path.exists():
        print("No demo launcher state found.")
        return
    state = json.loads(state_path.read_text(encoding="utf-8"))
    try:
        response = httpx.get(FIXTURE_BASE + "/health", timeout=2, trust_env=False)
        response.raise_for_status()
        if response.json().get("run_id") != state["run_id"]:
            raise RuntimeError("Demo run id does not match; no stop request sent")
    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError("Demo fixture server is not reachable; no stop request sent") from exc
    (DEMO_DIR / "stop.request").touch()
    print("Requested demo shutdown; normal services are unaffected.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["start", "tokens", "stop"])
    args = parser.parse_args()
    os.chdir(ROOT)
    try:
        if args.action == "stop":
            stop()
        elif args.action == "tokens":
            write_environment(settings())
        else:
            start(settings())
    except (RuntimeError, httpx.HTTPError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
