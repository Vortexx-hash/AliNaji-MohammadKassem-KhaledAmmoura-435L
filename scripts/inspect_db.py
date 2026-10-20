"""Read schema, foreign keys and records from an existing owned database for evidence capture."""
import argparse
import json
import sqlite3
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=["users", "logs", "notifications", "threats", "vulnerabilities", "reports"])
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    args = parser.parse_args()
    path = (args.data_dir / f"{args.service}.db").resolve()
    if not path.is_file():
        parser.error("Start the service first; database does not exist")
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence' ORDER BY name")]
        result = {"database": str(path), "integrity_check": conn.execute("PRAGMA integrity_check").fetchone()[0], "tables": {}}
        for table in tables:
            # Identifiers originate from SQLite's own catalog, escaped as identifiers.
            name = '"' + table.replace('"', '""') + '"'
            result["tables"][table] = {
                "schema": conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()[0],
                "foreign_keys": [dict(r) for r in conn.execute(f"PRAGMA foreign_key_list({name})")],
                "row_count": conn.execute(f"SELECT count(*) FROM {name}").fetchone()[0],
                "records": [dict(r) for r in conn.execute(f"SELECT * FROM {name} LIMIT 50")],
            }
        print(json.dumps(result, indent=2))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
