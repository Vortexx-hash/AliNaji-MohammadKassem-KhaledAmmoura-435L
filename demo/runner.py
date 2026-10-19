"""Internal child-process entry point for scripts.demo."""
import argparse

import uvicorn

PORTS = {"dependencies": 8010, "threats": 8104, "vulnerabilities": 8107, "reports": 8106}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=list(PORTS))
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if args.service == "dependencies":
        from demo.dependencies import create_app
        app = create_app(run_id=args.run_id)
    else:
        from demo.apps import create_app
        app = create_app(args.service)
    uvicorn.run(app, host="127.0.0.1", port=PORTS[args.service], access_log=False)


if __name__ == "__main__":
    main()
