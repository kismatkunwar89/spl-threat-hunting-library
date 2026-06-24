# Pass-the-Ticket

**Use when:** hunting lateral movement via a stolen/exported Kerberos ticket reused on a
different host than where it was originally issued (e.g. Mimikatz `sekurlsa::tickets /export`
+ `kerberos::ptt`).

## Detection - orphaned service ticket request (`EventCode 4769` without a preceding `4768`)
A legitimate flow is TGT (`4768`) then service ticket (`4769`) from the same user, same source.
A ticket imported on a different host shows the service ticket with no matching TGT request
from that user+source pairing.
```spl
index=* source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770) service_name!="krbtgt"
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| stats count, values(service_name) as service_name, min(_time) as _time by username, src_ip_4, ComputerName
| sort - count
```
*`maxspan=10h` isn't arbitrary - it matches AD's default Kerberos max ticket lifetime
(`MaxTicketAge`). `service_name!="krbtgt"` drops renewal-adjacent noise. Excludes machine
accounts both as a bare suffix and in UPN form (`name$@REALM`).*

**This is a starting point, not a verdict.** The "orphaned ticket" shape isn't unique to an
attack - a cached ticket reused across a long session, or a TGT/TGS split across different DCs
in a multi-DC environment, produces the same shape. A high repeat count doesn't guarantee
malicious (a legitimate service account can repeat too) and a low count doesn't guarantee
benign (a single hit from an obviously-suspicious account name is still worth checking).
Corroborate with: origin (does the source tie to known-bad infrastructure?), cross-reference
(does this account/service show up in another, independent detection too?), and repetition
(one orphan vs. a sustained pattern).

**Scaling note:** `transaction` is expensive at high event volume, and multi-DC/NAT topology
generates "orphaned" tickets from infrastructure alone, not just attackers. At enterprise scale,
replace `transaction` with a `stats`-based correlation (or join on `LogonId`, which is
authoritative to one session regardless of which IP/DC touched it).

**Related:** [kerberos-tgt-volume.md](kerberos-tgt-volume.md) · [golden-silver-ticket.md](golden-silver-ticket.md) reuses this exact logic for Golden Ticket detection.
