# 04 - Credential Access

Credential theft and the authentication anomalies around it: LSASS dumping, domain
replication, Kerberos ticket volume, and login bursts. (Auth anomalies here are *indicators* -
they don't by themselves prove credential theft.)

| Leaf | What it does |
|---|---|
| [lsass-dumping.md](lsass-dumping.md) | A non-lsass process opening a handle to lsass + naming the dump method (EC10 + EC1) |
| [dcsync.md](dcsync.md) | A non-machine account requesting AD replication rights (EC4662) |
| [kerberos-tgt-volume.md](kerberos-tgt-volume.md) | Accounts with the highest Kerberos TGT request counts (EC4768) |
| [login-burst-window.md](login-burst-window.md) | Accounts whose entire login history fits a tight window (EC4624 + range) |
| [llmnr-nbtns-poisoning.md](llmnr-nbtns-poisoning.md) | Responder-style name-resolution poisoning and relay (EC22 + EC4648 domain allowlist) |

**Auth router:** for "suspicious account / authentication activity" generally, see also
[05 account-spread](../05-lateral-movement/account-spread.md) (one account → many machines).
