# DCSync - domain replication abuse

**Use when:** you suspect an attacker extracting AD secrets via replication - a non-machine
account requesting replication rights = full domain compromise.

## Detection - `EventCode 4662` (Security)
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4662 Access_Mask="0x100" Account_Name!="*$"
| search Properties="*{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}*" OR Properties="*{19195a5b-6da0-11d0-afd3-00c04fd930c9}*"
| stats count by _time, ComputerName, Account_Name, Access_Mask, Properties
```
*`{1131f6ad-...}` is `DS-Replication-Get-Changes-All`. `Access_Mask=0x100` is Control Access. Excluding `*$` removes legitimate machine-driven replication, isolating the suspicious user.*
*Post-compromise: if confirmed, rotate the `krbtgt` account twice (golden-ticket mitigation).*

**Related:** [kerberos-tgt-volume.md](kerberos-tgt-volume.md) · [05-lateral-movement/account-spread.md](../05-lateral-movement/account-spread.md).
