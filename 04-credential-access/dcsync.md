# DCSync - domain replication abuse

**Use when:** you suspect an attacker extracting AD secrets via replication - a non-machine
account requesting replication rights = full domain compromise.

## Primary detection - `EventCode 4662` (Security), text match
```spl
index=* EventCode=4662 Message="*Replicating Directory Changes*" Account_Name!="*$"
| rex field=Message "(?<property>Replicating Directory Changes.*)"
| table _time, Account_Name, Object_Name, Object_Server, property
```
*Tested against real data: the `Properties` field often holds only a generic label ("Control
Access"), not the underlying GUID - the GUID never appears anywhere in the rendered log, only
the friendly name does. Text-matching the `Message` field is what actually works. Excluding
`*$` removes legitimate machine-driven DC-to-DC replication, isolating a standard user account.
Watch for inner-wildcard spaces (`" *term* "` silently matches nothing).*

## Fallback - GUID match (verify your environment exposes it before relying on this)
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4662 Access_Mask="0x100" Account_Name!="*$"
| search Properties="*{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}*" OR Properties="*{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}*"
| stats count by _time, ComputerName, Account_Name, Access_Mask, Properties
```
*`{1131f6aa-...}` is `DS-Replication-Get-Changes`, `{1131f6ad-...}` is `...-Get-Changes-All` - a
full DCSync needs both rights, so check for either. GUIDs are stable across locale/Windows
version *when exposed*, but not every environment's log rendering includes them - confirm with
a `transpose` on a real replication event before trusting this over the text match above.*
*Post-compromise: if confirmed, rotate the `krbtgt` account twice (golden-ticket mitigation).*

**Related:** [kerberos-tgt-volume.md](kerberos-tgt-volume.md) · [05-lateral-movement/account-spread.md](../05-lateral-movement/account-spread.md).
