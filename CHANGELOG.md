# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Agent protocol with a closed, strictly validated action set (no remote shell).
- Internal CA, one-time enrolment tokens with CA fingerprint pinning, mTLS agent gateway, certificate revocation and renewal.
- SQLite store with embedded migrations, audit log, host presence (online/offline) tracking.
- `sentrix-server token create`, `sentrix-agent enroll|run`.
- Repository bootstrap: Go module, layout, Makefile, CI, lint config, licence, docs skeleton.
