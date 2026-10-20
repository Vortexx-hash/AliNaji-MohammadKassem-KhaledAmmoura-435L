-- Users and Identity Management (Mohamed Kassem). Passwords are stored only as bcrypt hashes.
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL CHECK(length(trim(full_name)) BETWEEN 1 AND 255),
    username TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK(length(username) BETWEEN 3 AND 30),
    email TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK(length(email) BETWEEN 6 AND 254),
    password_hash TEXT NOT NULL,
    department TEXT NOT NULL CHECK(length(trim(department)) BETWEEN 1 AND 255),
    role TEXT NOT NULL CHECK(role IN ('Security Administrator','Security Analyst','Regular Employee/User','Auditor')),
    account_status TEXT NOT NULL DEFAULT 'Active' CHECK(account_status IN ('Active','Inactive','Suspended')),
    created_date TEXT NOT NULL,
    last_login_date TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
