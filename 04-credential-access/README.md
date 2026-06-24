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
| [kerberoasting.md](kerberoasting.md) | RC4-encrypted service ticket requests against AD service accounts (EC4769) |
| [as-rep-roasting.md](as-rep-roasting.md) | TGT requests against accounts with pre-auth disabled (EC4768) |
| [pass-the-hash.md](pass-the-hash.md) | LSASS access correlated with a NewCredentials logon on the same host (EC10 + EC4624) |
| [pass-the-ticket.md](pass-the-ticket.md) | Service ticket request with no preceding TGT - a stolen ticket reused from a different host (EC4768/4769/4770) |
| [overpass-the-hash.md](overpass-the-hash.md) | A stolen hash used to request a Kerberos TGT directly, bypassing lsass (EC3 port 88) |
| [golden-silver-ticket.md](golden-silver-ticket.md) | Forged TGT/TGS tickets - reuses Pass-the-Ticket logic plus phantom-user and new-privilege checks (EC4624/4672/4769) |
| [ad-delegation-abuse.md](ad-delegation-abuse.md) | Delegation discovery via PowerShell logging, then S4U exploitation (EC4104 + EC3 port 88) |
| [dcshadow.md](dcshadow.md) | A non-DC machine registering a Global Catalog SPN to impersonate a Domain Controller (EC4742) |
| [rdp-bruteforce.md](rdp-bruteforce.md) | RDP connection-volume + username-breadth brute force (Zeek `bro:rdp:json`) |
| [kerberos-asreq-enumeration.md](kerberos-asreq-enumeration.md) | Failed AS-REQ volume + username breadth - enumeration vs. guessing (Zeek `bro:kerberos:json`) |
| [golden-ticket-network.md](golden-ticket-network.md) | Orphaned TGS request with no preceding AS-REQ (Zeek `bro:kerberos:json`) |
| [zerologon.md](zerologon.md) | Netlogon RPC operation volume spike, CVE-2020-1472 (Zeek `bro:dce_rpc:json`) |

**Auth router:** for "suspicious account / authentication activity" generally, see also
[05 account-spread](../05-lateral-movement/account-spread.md) (one account → many machines).
