CREATE TABLE series (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id  TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name     TEXT NOT NULL,
    labels   TEXT NOT NULL DEFAULT '',
    last_ts  INTEGER NOT NULL DEFAULT 0,
    last_val REAL NOT NULL DEFAULT 0,
    UNIQUE (host_id, name, labels)
);

CREATE TABLE metrics_raw (
    series_id INTEGER NOT NULL REFERENCES series(id) ON DELETE CASCADE,
    ts        INTEGER NOT NULL,
    value     REAL NOT NULL,
    PRIMARY KEY (series_id, ts)
) WITHOUT ROWID;
CREATE INDEX metrics_raw_ts ON metrics_raw(ts);

CREATE TABLE metrics_1m (
    series_id INTEGER NOT NULL REFERENCES series(id) ON DELETE CASCADE,
    ts        INTEGER NOT NULL,
    avg       REAL NOT NULL,
    min       REAL NOT NULL,
    max       REAL NOT NULL,
    PRIMARY KEY (series_id, ts)
) WITHOUT ROWID;
CREATE INDEX metrics_1m_ts ON metrics_1m(ts);

CREATE TABLE metrics_1h (
    series_id INTEGER NOT NULL REFERENCES series(id) ON DELETE CASCADE,
    ts        INTEGER NOT NULL,
    avg       REAL NOT NULL,
    min       REAL NOT NULL,
    max       REAL NOT NULL,
    PRIMARY KEY (series_id, ts)
) WITHOUT ROWID;
CREATE INDEX metrics_1h_ts ON metrics_1h(ts);
