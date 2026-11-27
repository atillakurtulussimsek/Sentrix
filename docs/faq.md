[Türkçe](tr/faq.md) · **English**

# FAQ

**Does Sentrix send my package lists anywhere?**
No. Vulnerability feeds are downloaded to your server and matching happens locally. Outbound requests go to
the feed sources (Debian, OSV/Google Cloud Storage, CISA, FIRST, NVD) and to the notification channels you set up.

**Why does a CVE show "no fix yet"?**
The distribution has acknowledged the issue but not shipped a fixed package. Sentrix still lists it (lower risk
score) because it affects you; accept or ignore it with an expiry if appropriate.

**The CVE list differs from scanner X.**
Sentrix uses the distribution's own advisories and version rules, so backported fixes are respected
(e.g. `openssl 3.0.15-1~deb12u1` is fixed even though upstream calls the fix 3.0.14). Generic scanners comparing
upstream versions report many false positives.

**Rocky Linux?**
Rocky's own OSV export is incomplete, so Rocky hosts are also matched against AlmaLinux advisories (same RHEL
sources and package versions). Fedora and RHEL itself are monitored and inventoried but have no vulnerability
data source in v0.1.

**Can the server run commands on my hosts?**
Only the typed actions listed in [agent-security.md](agent-security.md). There is no remote shell. Set
`allow_patching: false` for monitoring-only hosts.

**How big does the database get?**
Metrics: roughly 150 series per host; with default retention ~30–60 MB per host-year. Vulnerability data:
Ubuntu's feed is the largest (~750k rows for 24.04, a few hundred MB on disk); others are small.

**Can I use PostgreSQL?**
Not yet — SQLite (WAL) comfortably handles hundreds of hosts. The storage layer uses portable SQL so a
PostgreSQL backend is on the roadmap.

**I lost the admin password / 2FA device.**
`sentrix-server user reset-password --username admin` (in Docker: `docker compose exec sentrix …`). This clears
2FA and signs the user out everywhere; the action is audit-logged.

**Agents behind NAT / firewalls?**
Agents only make outbound HTTPS connections to port 8443 of the server. Nothing needs to reach the host.

**Air-gapped?**
Mirror the feed files and point `feeds.*_url` to your mirror; agents are downloaded from the server itself.

**Can I use the UI in English?**
Yes. Each user picks their language from the picker in the sidebar, on the sign-in page or in *Account* settings.
Change the server default (also used for notifications) with `SENTRIX_LANGUAGE=en`; see
[configuration](configuration.md#language).

### Why is a kernel CVE still open after I patched?

Only the running kernel counts. If a fixed kernel is installed but the host has not been rebooted, the finding stays
open and is marked **reboot required**. After the reboot (and the next inventory) it closes; old fallback kernels
that are still installed are ignored.
