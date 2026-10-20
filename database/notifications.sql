-- Notification and Alert Management (Mohamed Kassem).
-- user_references holds recipients VERIFIED through the Users API, so notifications keep a real foreign key
-- inside this service's database. It is a projection, not a copy of the Users table.
CREATE TABLE IF NOT EXISTS user_references (
    user_id INTEGER PRIMARY KEY CHECK(user_id > 0),
    username TEXT,
    verified_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES user_references(user_id) ON DELETE RESTRICT,
    title TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 255),
    message TEXT NOT NULL CHECK(length(trim(message)) BETWEEN 1 AND 4000),
    notification_type TEXT NOT NULL CHECK(notification_type IN
        ('Incident Assignment','Security Alert','System Notification','Threat Alert','Vulnerability Alert')),
    severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
    status TEXT NOT NULL DEFAULT 'Unread' CHECK(status IN ('Unread','Read')),
    creation_date TEXT NOT NULL,
    read_date TEXT,
    CHECK ((status = 'Read' AND read_date IS NOT NULL) OR (status = 'Unread' AND read_date IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_type_status ON notifications(notification_type, status);
CREATE TRIGGER IF NOT EXISTS notifications_start_unread
BEFORE INSERT ON notifications WHEN NEW.status != 'Unread'
BEGIN SELECT RAISE(ABORT, 'Notification must start Unread'); END;
CREATE TRIGGER IF NOT EXISTS notifications_read_once
BEFORE UPDATE OF status ON notifications WHEN OLD.status = 'Read' AND NEW.status != 'Read'
BEGIN SELECT RAISE(ABORT, 'A read notification cannot become unread'); END;
