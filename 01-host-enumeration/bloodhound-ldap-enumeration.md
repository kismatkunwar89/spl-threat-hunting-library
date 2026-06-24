# BloodHound / SharpHound LDAP enumeration

**Use when:** you suspect an attacker is mapping AD relationships (users, groups, ACLs, trusts,
sessions) via BloodHound/SharpHound rather than native commands. Default Windows Event Logs do
not record LDAP queries well - even Event 1644 (LDAP performance log) misses most BloodHound
activity. Requires an ETW wrapper (e.g. SilkETW/SilkService capturing
`Microsoft-Windows-LDAP-Client`) feeding a custom source.

## Environment check - confirm the schema first
The ETW payload lands as JSON text inside a single `Message` field, not pre-extracted Splunk
fields. Always parse and inspect before building a detection on top of it.
```spl
index=* source="<silk_log_source>"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
```

## Primary detection - known signature
BloodHound's default user-collection step queries `sAMAccountType=805306368`. Counting repeats
of this one filter per process catches the default run.
```spl
index=* source="<silk_log_source>"
| spath input=Message
| rename XmlEventData.* as *
| search SearchFilter="*(samAccountType=805306368)*"
| stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId
| where count > 10
| convert ctime(maxTime)
```
*Watch the wildcard spacing - `"* term *"` with literal spaces inside the quotes silently
matches nothing if the field value has no surrounding whitespace. Use `"*term*"`.*

## Statistical variant - breadth, bypass-resistant
A single hardcoded filter only catches collection runs that include that exact step. An
attacker running a partial collection (e.g. only groups/ACLs/trusts) or a renamed/reflectively
loaded binary never trips a name- or filter-specific check. Volume of *distinct* LDAP filters
fired by one process is the signal that survives both evasions.
```spl
index=* source="<silk_log_source>"
| spath input=Message
| rename XmlEventData.* as *
| eval is_known_signature=if(match(SearchFilter, "samAccountType=805306368"), 1, 0)
| stats min(_time) as _time, max(_time) as maxTime, count as total_queries, dc(SearchFilter) as distinct_filters, sum(is_known_signature) as known_signature_hits by ComputerName, ProcessName, ProcessId
| where distinct_filters > 20 OR known_signature_hits > 10
| convert ctime(maxTime)
```
*Threshold is tunable - in a tested run, SharpHound produced 2,845 distinct filters against a
next-highest of 7 from any legitimate process, so `> 20` has wide margin. Lower it only if
hunting a throttled/slow collection run. `ProcessName` is kept for triage context, not as the
match condition - that's what makes this resistant to renaming the binary.*

**Related:** [lolbin-recon.md](lolbin-recon.md) for the native-command half of domain recon -
attackers typically use both methods, native commands for quick checks and BloodHound for full
relationship mapping.
