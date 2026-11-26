CREATE TABLE channels (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL CHECK (kind IN ('email','telegram','discord','slack','ntfy','webhook')),
    config     TEXT NOT NULL,         -- JSON, secrets sealed
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE alert_rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('threshold','state','vulnerability','patch')),
    config      TEXT NOT NULL,        -- JSON (see internal/notify/rules.go)
    severity    TEXT NOT NULL DEFAULT 'warning',
    channels    TEXT NOT NULL DEFAULT '',  -- comma-separated channel IDs ('' = all enabled)
    for_seconds INTEGER NOT NULL DEFAULT 0,
    cooldown_seconds INTEGER NOT NULL DEFAULT 3600,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
);

CREATE TABLE alerts (
    id           TEXT PRIMARY KEY,
    rule_id      TEXT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    host_id      TEXT NOT NULL DEFAULT '',
    dedup_key    TEXT NOT NULL,
    status       TEXT NOT NULL,          -- pending|firing|resolved
    severity     TEXT NOT NULL,
    subject      TEXT NOT NULL DEFAULT '',
    message      TEXT NOT NULL,
    value        REAL NOT NULL DEFAULT 0,
    started_at   INTEGER NOT NULL,
    fired_at     INTEGER NOT NULL DEFAULT 0,
    resolved_at  INTEGER NOT NULL DEFAULT 0,
    last_notified INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX alerts_open ON alerts(dedup_key, status);
CREATE INDEX alerts_status ON alerts(status, started_at);

-- last firing notification per dedup key (suppresses flapping within the cooldown)
CREATE TABLE alert_notify_state (
    dedup_key     TEXT PRIMARY KEY,
    last_fired    INTEGER NOT NULL
);

CREATE TABLE notification_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    channel_id TEXT NOT NULL,
    alert_id   TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL,     -- firing|resolved|digest|test|event
    status     TEXT NOT NULL,     -- sent|failed
    error      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX notification_log_ts ON notification_log(ts);
