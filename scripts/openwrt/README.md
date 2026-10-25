# OpenWrt development helpers

These opt-in tools support isolated server builds, XFRM experiments, traffic
inspection and acceptance tests. They are not a general-purpose installer and
are never run by the Windows client or hosted CI. They can change router
configuration when explicitly executed with administrative access.

The checked-in topology, pool and identities are examples, not a deployment.
Adapt all lab addresses, routing targets, pool ranges, firewall scopes and
identities before a live run. Keep actual site settings and connection exports
under ignored `private/`, not in public documentation or commits. The lab's
obvious test-only key must never be reused on a real server.

Credential import requires an explicit router and expected identities:

```powershell
.\scripts\openwrt\Import-Credentials.ps1 -Router <VPN_GATEWAY> -ExpectedLocalId <LOCAL_ID> -ExpectedRemoteId <REMOTE_ID> -VpnConfFile .\private\client.tgb
```

The importer supports the original name-based client identity workflow. Review
the pool, DNS, XFRM and firewall configuration separately. It transmits the key
through an SSH-encrypted stdin pipe, not process arguments or logs, and retains
SSH host-key verification. Never commit the source credential export.

`Ensure-IdentityAlias.uc` takes the new DNS identity followed by the expected
existing server and client identities. Add `--check` to validate without writing.
`Rekey-Lab.sh prepare` takes the private rollback directory and an explicit
expected source-client identity. Its other actions use the existing rollback
directory. Both refuse mismatching or ambiguous ownership instead of guessing.

Back up the router and validate module/firmware compatibility before deployment.
Use a dedicated test connection; do not overwrite another user's settings.
Rollback archives, packet captures, controller credentials and raw diagnostics
must remain private. `Migrate-RouterWork.ps1` also requires an explicit router;
it transfers work into private storage and does not remove the remote files.
