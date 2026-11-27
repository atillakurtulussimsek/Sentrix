-- Set when a finding's fix is installed in a newer kernel that is not running yet.
ALTER TABLE findings ADD COLUMN reboot_required INTEGER NOT NULL DEFAULT 0;
