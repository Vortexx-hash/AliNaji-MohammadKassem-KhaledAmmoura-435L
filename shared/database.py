import sqlite3
from contextlib import contextmanager
from pathlib import Path


class Database:
    """Short-lived connections; transaction rollback and foreign keys on every connection."""

    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def initialize(self, *scripts: str):
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            for script in scripts:
                conn.executescript(script)


def schema(name: str) -> str:
    return (Path(__file__).resolve().parents[1] / "database" / name).read_text(encoding="utf-8")
