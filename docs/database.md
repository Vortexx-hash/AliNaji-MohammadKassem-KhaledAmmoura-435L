# Database design (Ali Naji)

Each service owns a SQLite file. Every connection enables foreign keys and uses transactions. WAL supports concurrent readers; short writes have a ten-second busy timeout. Parameterized SQL binds all input values. SQL files are idempotent initial schemas; future structural changes need explicit versioned migrations.

## Threat database (Ali Naji)

`data/threats.db`: `threats.id` is an autoincrement integer primary key. `threat_type`, `threat_value`, `description`, `severity`, `source`, and `date_added` contain all required assignment fields. The composite unique key prevents duplicate type/value pairs, including concurrent inserts. CHECK constraints enforce enums and nonempty fields. Type/severity indexes support filtering. Normalization occurs before insertion. No user foreign key is invented because Threats has none in the assignment.

## Audit transport tables (Ali Naji)

Each service database also contains `audit_outbox` (UUID primary key and event content) and `audit_delivery` (one delivery receipt per event; foreign key to outbox). Triggers prevent changing/deleting original events. These tables preserve our events until delivery to the teammate's Logs API; they do not expose audit management endpoints. `user_id` is an external identity reference, not a local Users-table foreign key.

Inspect the live database using DB Browser for SQLite or the `sqlite3` Python module after executing APIs. Do not submit empty databases or seeded fixtures as API execution evidence.
