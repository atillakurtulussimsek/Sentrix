# Proxmox VE snapshot integration

Sentrix can snapshot a VM or container right before patching it, and abort that host if the snapshot fails.

1. **Create an API token** in Proxmox: *Datacenter → Permissions → API Tokens → Add* (e.g. user
   `sentrix@pve`, token ID `patch`). Give the token (or its user, without privilege separation) a role with
   `VM.Snapshot` (and `VM.Audit`) on the VMs/pools Sentrix should snapshot.
2. **Add the hook** in *Settings → Snapshot hooks*: API URL (`https://pve.example.com:8006`), token ID
   (`sentrix@pve!patch`) and secret. For self-signed certificates paste the certificate's SHA-256
   fingerprint (*Node → System → Certificates*) instead of disabling verification. Click **test connection**.
3. **Map hosts** under each host's *Patches & actions* tab: node name and VM ID (`105` for QEMU,
   `lxc/105` for a container). A default node can be set on the hook.
4. **Use it** in a patch plan or policy (snapshot hook + "abort host if its snapshot fails").

Snapshots are named `sentrix-<plan>-<UTC timestamp>` and described with the plan name. Sentrix does not delete
snapshots — remove them after you verified the patched system.

## Generic webhook hook

Any other snapshot mechanism (ZFS, LVM, cloud APIs, backup tools) can be triggered by a webhook: Sentrix POSTs

```json
{"event": "pre_patch", "target": {"plan_id": "…", "plan_name": "…", "host_id": "…", "hostname": "web-1"}, "time": "…"}
```

with `X-Sentrix-Signature: sha256=<HMAC>` if a secret is set. Answer 2xx when the snapshot is done (optionally
`{"snapshot": "name"}`); anything else counts as a failed snapshot.
