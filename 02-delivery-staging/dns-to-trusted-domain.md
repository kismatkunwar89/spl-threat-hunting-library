# DNS to a trusted / allow-listed domain

**Use when:** you suspect a payload being pulled from (or C2 hiding behind) a reputable,
allow-listed domain that beats proxy filtering. This is **inference, not proof** — EC22 shows
only that a process *resolved* a domain, not that it downloaded or beaconed.

## Detection — `EventCode 22` (DNS)
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=22 QueryName="*<domain>*"
| stats count by Image, QueryName
```
*Read it as: unexpected `Image` (e.g. `svchost.exe`, `powershell.exe`) + trusted domain → investigate for a download or C2 channel. The resolution itself proves neither.*

**Related:** this doubles as a C2 angle — see [06-c2-exfil/](../06-c2-exfil/). For what the process did after resolving, pivot via [90-pivots/process-activity-tree.md](../90-pivots/process-activity-tree.md).
