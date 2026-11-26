CREATE TABLE vulns (
    id            TEXT PRIMARY KEY,          -- CVE-YYYY-NNNN (or advisory id if no CVE)
    summary       TEXT NOT NULL DEFAULT '',
    published     INTEGER NOT NULL DEFAULT 0,
    cvss_score    REAL NOT NULL DEFAULT 0,
    cvss_vector   TEXT NOT NULL DEFAULT '',
    cvss_source   TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT '',   -- critical|high|medium|low|unknown
    epss          REAL NOT NULL DEFAULT 0,
    epss_pct      REAL NOT NULL DEFAULT 0,
    kev           INTEGER NOT NULL DEFAULT 0,
    kev_added     TEXT NOT NULL DEFAULT '',
    kev_due       TEXT NOT NULL DEFAULT '',
    kev_ransomware TEXT NOT NULL DEFAULT '',
    nvd_checked   INTEGER NOT NULL DEFAULT 0
);

-- Distro-specific affected/fixed data. ecosystem: debian:12, ubuntu:24.04, alpine:3.19, rocky:9, almalinux:9
CREATE TABLE vuln_affected (
    source        TEXT NOT NULL,              -- feed name
    ecosystem     TEXT NOT NULL,
    package       TEXT NOT NULL,
    vuln_id       TEXT NOT NULL,
    advisory      TEXT NOT NULL DEFAULT '',
    introduced    TEXT NOT NULL DEFAULT '',
    fixed         TEXT NOT NULL DEFAULT '',   -- '' = no fix available
    distro_severity TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (ecosystem, package, vuln_id, source, advisory)
) WITHOUT ROWID;
CREATE INDEX vuln_affected_vuln ON vuln_affected(vuln_id);

CREATE TABLE findings (
    host_id      TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    vuln_id      TEXT NOT NULL,
    package      TEXT NOT NULL,              -- matched package (source name for dpkg/apk)
    installed    TEXT NOT NULL,
    fixed        TEXT NOT NULL DEFAULT '',
    advisory     TEXT NOT NULL DEFAULT '',
    binaries     TEXT NOT NULL DEFAULT '',   -- installed binary packages built from it
    exposed      TEXT NOT NULL DEFAULT '',   -- listening service evidence
    severity     TEXT NOT NULL DEFAULT 'unknown', -- effective severity (CVSS, else distro rating)
    risk         REAL NOT NULL DEFAULT 0,
    risk_json    TEXT NOT NULL DEFAULT '',
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    PRIMARY KEY (host_id, vuln_id, package)
) WITHOUT ROWID;
CREATE INDEX findings_vuln ON findings(vuln_id);

-- Resolved findings history (so "disappeared after upgrade" is visible).
CREATE TABLE findings_resolved (
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    vuln_id     TEXT NOT NULL,
    package     TEXT NOT NULL,
    installed   TEXT NOT NULL,
    resolved_at INTEGER NOT NULL
);
CREATE INDEX findings_resolved_host ON findings_resolved(host_id, resolved_at);

CREATE TABLE vuln_exceptions (
    id          TEXT PRIMARY KEY,
    vuln_id     TEXT NOT NULL,
    host_id     TEXT NOT NULL DEFAULT '',    -- '' = all hosts
    kind        TEXT NOT NULL CHECK (kind IN ('accepted','ignored')),
    reason      TEXT NOT NULL,
    expires_at  INTEGER NOT NULL DEFAULT 0,  -- 0 = never
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX vuln_exceptions_vuln ON vuln_exceptions(vuln_id);

CREATE TABLE feed_status (
    feed          TEXT PRIMARY KEY,
    last_attempt  INTEGER NOT NULL DEFAULT 0,
    last_success  INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT NOT NULL DEFAULT '',
    records       INTEGER NOT NULL DEFAULT 0,
    etag          TEXT NOT NULL DEFAULT ''
);
