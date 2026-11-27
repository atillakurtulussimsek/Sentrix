-- Per-user UI language; empty means "use the server default".
ALTER TABLE users ADD COLUMN language TEXT NOT NULL DEFAULT '';
