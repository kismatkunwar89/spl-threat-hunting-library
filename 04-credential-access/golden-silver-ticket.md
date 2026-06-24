# Golden Ticket / Silver Ticket

**Use when:** hunting forged Kerberos tickets - a Golden Ticket forges a TGT using the `krbtgt`
hash (domain-wide persistent access), a Silver Ticket forges a TGS using a specific service
account's hash (access to just that service, but able to impersonate any user on it). The
forging itself happens offline and isn't observable - detection has to focus on how the forged
ticket gets *used*.

## Golden Ticket - reuses Pass-the-Ticket detection directly
A forged Golden Ticket is presented to a service without ever going through a real TGT request,
so it shows up exactly like a Pass-the-Ticket orphaned-ticket event.
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
See [pass-the-ticket.md](pass-the-ticket.md) for the full breakdown and the same-shape-can-be-benign caveat.

## Silver Ticket - phantom users (`EventCode 4624` vs. a known-user lookup)
Prerequisite - build a lookup of accounts with a real creation record:
```spl
index=* earliest=0 EventCode=4720
| stats min(_time) as _time, values(EventCode) as EventCode by user
| outputlookup users.csv
```
Then flag logons by a user with no matching creation record:
```spl
index=* earliest=0 EventCode=4624 user!=*$
| stats min(_time) as firstTime, values(ComputerName) as ComputerName, values(EventCode) as EventCode by user, TargetUserSid
| lookup users.csv user as user OUTPUT EventCode as Events
| where isnull(Events) AND NOT match(TargetUserSid, "^NT AUTHORITY\\\\") AND NOT match(TargetUserSid, "^Window Manager\\\\") AND NOT match(TargetUserSid, "^Font Driver Host\\\\") AND NOT match(TargetUserSid, "\\\\(Administrator|Guest|krbtgt)$")
| convert ctime(firstTime)
```
*`TargetUserSid` often holds the resolved friendly name, not a raw numeric SID - check your data
before assuming a RID-suffix regex will work. The exclusions here drop OS pseudo-accounts,
machine accounts, and the three built-ins that never get a `4720` (created at domain-promotion
time, not by an admin action) - those three are universal AD defaults, not environment-specific
values, safe to hardcode.*

**Caveat:** this only catches a ticket forged for a username that was never created at all. The
more common move - forging a ticket as a real, existing account - won't trip this; that account
already has a legitimate creation record. Zero results here means this specific angle doesn't
apply, not that nothing happened.

## Silver Ticket - new special privileges (`EventCode 4672`)
Catches impersonation of a real account regardless of whether the username is fake - flags any
account whose *first-ever* admin-equivalent logon falls in the most recent slice of the dataset.
```spl
index=* earliest=0 EventCode=4672
| eval Account_Name=lower(Account_Name)
| eventstats max(_time) as dataset_latest
| stats min(_time) as firstTime, values(ComputerName) as ComputerName, max(dataset_latest) as dataset_latest by Account_Name
| where firstTime > (dataset_latest - 86400)
| table firstTime, ComputerName, Account_Name
| convert ctime(firstTime)
```
*Anchor "recent" to the dataset's own latest event (`dataset_latest`), not real wall-clock
`now()` - comparing historical data against actual current time guarantees zero results.
Normalize case before grouping, or the same account splits across multiple rows.*

`EventCode=4672` fires automatically at logon if that session holds admin rights - it doesn't
record *how* those rights were obtained, so a forged ticket and a legitimate admin login look
identical to this event. An account that never had admin rights before suddenly having them is
the anomaly worth a look, not proof on its own.

**Related:** [pass-the-ticket.md](pass-the-ticket.md) · [ad-delegation-abuse.md](ad-delegation-abuse.md).
