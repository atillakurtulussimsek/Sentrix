CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE enroll_tokens (
    id          TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    note        TEXT NOT NULL DEFAULT '',
    group_name  TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER,
    host_id     TEXT
);

CREATE TABLE hosts (
    id              TEXT PRIMARY KEY,
    hostname        TEXT NOT NULL,
    machine_id      TEXT NOT NULL DEFAULT '',
    cert_serial     TEXT NOT NULL DEFAULT '',
    cert_not_after  INTEGER NOT NULL DEFAULT 0,
    revoked         INTEGER NOT NULL DEFAULT 0,
    agent_version   TEXT NOT NULL DEFAULT '',
    boot_time       INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL DEFAULT 0,
    group_name      TEXT NOT NULL DEFAULT '',
    tags            TEXT NOT NULL DEFAULT '',
    state_json      TEXT NOT NULL DEFAULT '',
    state_at        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX hosts_hostname ON hosts(hostname);

CREATE TABLE audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    actor    TEXT NOT NULL,
    action   TEXT NOT NULL,
    target   TEXT NOT NULL DEFAULT '',
    detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_ts ON audit_log(ts);
