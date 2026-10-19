CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type TEXT NOT NULL CHECK(threat_type IN ('IP Address','Domain','File Hash','Malware Signature','Other Indicators')),
    threat_value TEXT NOT NULL CHECK(length(threat_value) BETWEEN 1 AND 255),
    description TEXT NOT NULL CHECK(length(trim(description)) BETWEEN 1 AND 4000),
    severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
    source TEXT NOT NULL CHECK(length(trim(source)) BETWEEN 1 AND 255),
    date_added TEXT NOT NULL,
    UNIQUE(threat_type, threat_value)
);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(threat_type);
