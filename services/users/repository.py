import sqlite3

from fastapi import HTTPException

from services.users.security import hash_password, issue_token, verify_password, TOKEN_MINUTES
from shared.audit import utcnow


class UserRepository:
    def __init__(self, db, audit, settings):
        self.db, self.audit, self.settings = db, audit, settings

    def register(self, data, actor_id):
        values = data.model_dump(mode="json")
        values["password_hash"] = hash_password(values.pop("password"))
        values["account_status"], values["created_date"] = "Active", utcnow()
        try:
            with self.db.connect() as conn:
                cursor = conn.execute("INSERT INTO users (" + ",".join(values) + ") VALUES ("
                                      + ",".join("?" for _ in values) + ")", list(values.values()))
                row = dict(conn.execute("SELECT * FROM users WHERE id=?", (cursor.lastrowid,)).fetchone())
                self.audit.record(conn, actor_id or str(row["id"]), "USER_CREATED",
                                  f"Registered user {row['id']} ({row['username']}) with role {row['role']}")
        except sqlite3.IntegrityError as exc:
            raise self._duplicate(exc)
        self.audit.flush()
        return row

    def login(self, data):
        column, identifier = ("username", data.username) if data.username else ("email", data.email.lower())
        with self.db.connect() as conn:
            row = conn.execute(f"SELECT * FROM users WHERE {column}=?", (identifier,)).fetchone()
        if not verify_password(data.password, row["password_hash"] if row else None):
            self.audit.denied(str(row["id"]) if row else None, "LOGIN_FAILED",
                              f"Failed login for {column} '{identifier}': invalid credentials")
            raise HTTPException(401, "Invalid username/email or password")
        if row["account_status"] != "Active":
            self.audit.denied(str(row["id"]), "LOGIN_FAILED",
                              f"Blocked login for {row['username']}: account is {row['account_status']}")
            raise HTTPException(403, f"Account is {row['account_status'].lower()}; login is not allowed")
        with self.db.connect() as conn:
            conn.execute("UPDATE users SET last_login_date=? WHERE id=?", (utcnow(), row["id"]))
            row = dict(conn.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone())
            self.audit.record(conn, str(row["id"]), "LOGIN_SUCCESS", f"User {row['username']} logged in")
        self.audit.flush()
        return {"message": "Login successful", "access_token": issue_token(self.settings, row),
                "token_type": "bearer", "expires_in": TOKEN_MINUTES * 60, "user": row}

    def list(self):
        with self.db.connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM users ORDER BY id")]

    def get_by_username(self, username):
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    def update(self, user_id, data, actor_id):
        changes = data.model_dump(mode="json", exclude_unset=True)
        try:
            with self.db.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                before = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                if before is None:
                    raise HTTPException(404, "User not found")
                conn.execute("UPDATE users SET " + ",".join(f"{key}=?" for key in changes) + " WHERE id=?",
                             [*changes.values(), user_id])
                after = dict(conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())
                self.audit.record(conn, actor_id, "USER_UPDATED",
                                  f"Updated user {user_id}: {', '.join(sorted(changes))}")
                if after["role"] != before["role"]:
                    self.audit.record(conn, actor_id, "ROLE_CHANGED",
                                      f"User {user_id} role {before['role']} -> {after['role']}")
        except sqlite3.IntegrityError as exc:
            raise self._duplicate(exc)
        self.audit.flush()
        return dict(before), after

    def delete(self, user_id, actor_id):
        with self.db.connect() as conn:
            row = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "User not found")
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            self.audit.record(conn, actor_id, "USER_DELETED", f"Deleted user {user_id} ({row['username']})", "Warning")
        self.audit.flush()

    @staticmethod
    def _duplicate(exc):
        message = str(exc)
        if "users.username" in message:
            return HTTPException(409, "Username already exists")
        if "users.email" in message:
            return HTTPException(409, "Email is already registered")
        return exc
