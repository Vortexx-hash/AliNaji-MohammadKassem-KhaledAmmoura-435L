-- Read-only references to existing assets VERIFIED through the teammate's Assets API.
-- This is not an implementation or replacement of the Assets table/service.
CREATE TABLE IF NOT EXISTS asset_references (
    asset_id INTEGER PRIMARY KEY CHECK(asset_id > 0),
    asset_name TEXT,
    verified_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 255),
    description TEXT NOT NULL CHECK(length(trim(description)) BETWEEN 1 AND 4000),
    cve_identifier TEXT NOT NULL,
    cvss_score REAL NOT NULL CHECK(cvss_score BETWEEN 0 AND 10),
    severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
    affected_asset_id INTEGER NOT NULL REFERENCES asset_references(asset_id) ON DELETE RESTRICT,
    discovery_source TEXT NOT NULL CHECK(length(trim(discovery_source)) BETWEEN 1 AND 255),
    status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','Under Investigation','In Progress','Resolved','Closed')),
    creation_date TEXT NOT NULL,
    resolution_date TEXT,
    CHECK ((status IN ('Resolved','Closed') AND resolution_date IS NOT NULL
            AND julianday(resolution_date) IS NOT NULL AND julianday(resolution_date) >= julianday(creation_date))
           OR (status NOT IN ('Resolved','Closed') AND resolution_date IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_vuln_asset ON vulnerabilities(affected_asset_id);
CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_identifier);
CREATE INDEX IF NOT EXISTS idx_vuln_severity_status ON vulnerabilities(severity,status);
CREATE TRIGGER IF NOT EXISTS vulnerabilities_start_open
BEFORE INSERT ON vulnerabilities WHEN NEW.status != 'Open'
BEGIN SELECT RAISE(ABORT, 'Vulnerability must start Open'); END;
CREATE TRIGGER IF NOT EXISTS vulnerabilities_lifecycle
BEFORE UPDATE OF status ON vulnerabilities
WHEN NEW.status != OLD.status AND NOT (
    (OLD.status='Open' AND NEW.status='Under Investigation') OR
    (OLD.status='Under Investigation' AND NEW.status='In Progress') OR
    (OLD.status='In Progress' AND NEW.status='Resolved') OR
    (OLD.status='Resolved' AND NEW.status='Closed'))
BEGIN SELECT RAISE(ABORT, 'Invalid vulnerability status transition'); END;
