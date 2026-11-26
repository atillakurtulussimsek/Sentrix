CREATE TABLE host_inventory (
    host_id         TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    collected_at    INTEGER NOT NULL,
    received_at     INTEGER NOT NULL,
    os_id           TEXT NOT NULL DEFAULT '',
    os_version      TEXT NOT NULL DEFAULT '',
    os_codename     TEXT NOT NULL DEFAULT '',
    os_pretty       TEXT NOT NULL DEFAULT '',
    kernel          TEXT NOT NULL DEFAULT '',
    arch            TEXT NOT NULL DEFAULT '',
    virtualization  TEXT NOT NULL DEFAULT '',
    package_manager TEXT NOT NULL DEFAULT '',
    errors          TEXT NOT NULL DEFAULT ''
);

CREATE TABLE packages (
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    arch        TEXT NOT NULL DEFAULT '',
    version     TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    source_ver  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (host_id, name, arch)
) WITHOUT ROWID;
CREATE INDEX packages_source ON packages(source);
CREATE INDEX packages_name ON packages(name);

CREATE TABLE updates (
    host_id   TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    current   TEXT NOT NULL DEFAULT '',
    new       TEXT NOT NULL,
    security  INTEGER NOT NULL DEFAULT 0,
    origin    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (host_id, name)
) WITHOUT ROWID;

CREATE TABLE ports (
    host_id  TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    proto    TEXT NOT NULL,
    address  TEXT NOT NULL,
    port     INTEGER NOT NULL,
    pid      INTEGER NOT NULL DEFAULT 0,
    process  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (host_id, proto, address, port)
) WITHOUT ROWID;

CREATE TABLE host_images (
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    image   TEXT NOT NULL,
    PRIMARY KEY (host_id, image)
) WITHOUT ROWID;
