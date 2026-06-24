# DCShadow - rogue Domain Controller registration

**Use when:** hunting a stealthy AD-modification tactic where an attacker registers a rogue DC
to push unauthorized changes (e.g. silently adding an account to Domain Admins) without
generating the standard security logs a normal AD change would. To register, the rogue machine
must add a Global Catalog ServicePrincipalName to its own computer object.

## Detection - `EventCode 4742` (computer account changed), GC SPN added
```spl
index=* EventCode=4742
| rex field=Message "(?<gcspn>GC/[a-zA-Z0-9.\-/]+)"
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn
| search gcspn=*
```
*A Global Catalog SPN is formatted `GC/<hostname>/<domain>` - the `GC/` prefix is the anchor,
not a placeholder. Real Domain Controllers legitimately register their own GC SPN as normal
baseline behavior - the signal is a machine that has no business being a DC doing the same
thing.*

**Tuning notes:** baseline your real DCs' hostnames first so their expected GC registrations
don't need manual review every run; anything outside that known-DC set is the anomaly.

**Related:** [pass-the-ticket.md](pass-the-ticket.md) and [golden-silver-ticket.md](golden-silver-ticket.md) - DCShadow is often used to push the same kind of privilege change a forged ticket would grant, just via a different mechanism.
