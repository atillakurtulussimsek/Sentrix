CREATE TABLE commands (
    id          TEXT PRIMARY KEY,
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    action      TEXT NOT NULL,
    params      TEXT NOT NULL DEFAULT '',
    dry_run     INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'queued', -- queued|sent|ok|failed|rejected|expired
    plan_id     TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    sent_at     INTEGER NOT NULL DEFAULT 0,
    finished_at INTEGER NOT NULL DEFAULT 0,
    expires_at  INTEGER NOT NULL,
    result      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX commands_host_status ON commands(host_id, status);
CREATE INDEX commands_plan ON commands(plan_id);

CREATE TABLE policies (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    group_name    TEXT NOT NULL DEFAULT '',   -- '' = hosts without a group
    mode          TEXT NOT NULL CHECK (mode IN ('notify_only','auto_security','auto_all')),
    window_cron   TEXT NOT NULL DEFAULT '',   -- e.g. "CRON_TZ=Europe/Istanbul 0 3 * * SUN"
    window_minutes INTEGER NOT NULL DEFAULT 120,
    max_parallel  INTEGER NOT NULL DEFAULT 1,
    canary        INTEGER NOT NULL DEFAULT 1,
    reboot        TEXT NOT NULL DEFAULT 'never' CHECK (reboot IN ('never','if_required','always')),
    snapshot_hook TEXT NOT NULL DEFAULT '',   -- hook id; '' = none
    snapshot_required INTEGER NOT NULL DEFAULT 1,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    last_run      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE patch_plans (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    scope        TEXT NOT NULL CHECK (scope IN ('security','packages','all')),
    packages     TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL,   -- draft|dry_run|ready|approved|running|done|failed|cancelled
    policy_id    TEXT NOT NULL DEFAULT '',
    reboot       TEXT NOT NULL DEFAULT 'never',
    canary       INTEGER NOT NULL DEFAULT 0,
    max_parallel INTEGER NOT NULL DEFAULT 1,
    snapshot_hook TEXT NOT NULL DEFAULT '',
    snapshot_required INTEGER NOT NULL DEFAULT 1,
    created_by   TEXT NOT NULL,
    approved_by  TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    approved_at  INTEGER NOT NULL DEFAULT 0,
    started_at   INTEGER NOT NULL DEFAULT 0,
    finished_at  INTEGER NOT NULL DEFAULT 0,
    error        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE plan_hosts (
    plan_id      TEXT NOT NULL REFERENCES patch_plans(id) ON DELETE CASCADE,
    host_id      TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    position     INTEGER NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    step_cmd     TEXT NOT NULL DEFAULT '',     -- id of the command currently awaited
    dry_changes  TEXT NOT NULL DEFAULT '',     -- JSON []PackageChange from dry run
    changes      TEXT NOT NULL DEFAULT '',     -- JSON []PackageChange applied
    output       TEXT NOT NULL DEFAULT '',
    error        TEXT NOT NULL DEFAULT '',
    findings_before INTEGER NOT NULL DEFAULT -1,
    findings_after  INTEGER NOT NULL DEFAULT -1,
    reboot_required INTEGER NOT NULL DEFAULT 0,
    boot_time_before INTEGER NOT NULL DEFAULT 0,
    snapshot     TEXT NOT NULL DEFAULT '',
    started_at   INTEGER NOT NULL DEFAULT 0,
    finished_at  INTEGER NOT NULL DEFAULT 0,
    step_started INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (plan_id, host_id)
);

CREATE TABLE hooks (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL CHECK (kind IN ('proxmox','webhook')),
    config     TEXT NOT NULL,             -- JSON; secrets sealed
    created_at INTEGER NOT NULL
);

CREATE TABLE host_settings (
    host_id        TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    watch_services TEXT NOT NULL DEFAULT '',
    tls_endpoints  TEXT NOT NULL DEFAULT '',
    proxmox_vmid   TEXT NOT NULL DEFAULT '',
    proxmox_node   TEXT NOT NULL DEFAULT ''
);
