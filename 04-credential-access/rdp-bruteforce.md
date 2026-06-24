# RDP brute force (network)

**Use when:** hunting a high volume of RDP connection attempts from one source against one
target, via Zeek RDP logs rather than Windows Security logon events.

## Primary detection - `bro:rdp:json` connection volume + username breadth
```spl
index=* sourcetype="bro:rdp:json" earliest=0
| bin _time span=5m
| stats count, dc(cookie) as distinct_usernames, values(cookie) as usernames_tried by _time, id.orig_h, id.resp_h
| where count > <threshold>
| sort - count
```
*In this Zeek field, `cookie` holds the attempted username, not a session token - verify this
against your own data before trusting it. `distinct_usernames=1` means sustained guessing
against one already-known account; a high `distinct_usernames` count means a username-
enumeration spray instead. That distinction changes the response: one is targeted
password-guessing, the other is account discovery.*

*A baseline/stdev approach structurally cannot help here if the entire dataset is one source
flooding one destination - there's no separate "normal" population left to compare against.
Don't reach for `eventstats avg/stdev` when the attack traffic *is* the whole dataset; volume +
username breadth is the right detection shape for this case instead.*

**Related:** [kerberos-asreq-enumeration.md](kerberos-asreq-enumeration.md) (same
guessing-vs-enumeration distinction, different protocol) · [zerologon.md](zerologon.md) (another
network-volume credential-access detection).
