# Living-off-the-land enumeration binaries

**Use when:** you suspect an attacker is mapping the host or network with native Windows tools
to avoid dropping malware.

## Detection — `EventCode 1`
Native tools used to enumerate the environment and find escalation paths.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*\\ipconfig.exe" OR Image="*\\net.exe" OR Image="*\\whoami.exe" OR Image="*\\netstat.exe" OR Image="*\\nbtstat.exe" OR Image="*\\hostname.exe" OR Image="*\\tasklist.exe")
| stats count by Image, CommandLine
| sort - count
```
*Tune: admins run these too — pivot on `ParentImage` to tell a human admin from an automated payload firing them in sequence. Often the parent is the more interesting lead → [90-pivots/process-activity-tree.md](../90-pivots/process-activity-tree.md).*

**Related:** [03-execution-injection/abnormal-process-tree.md](../03-execution-injection/abnormal-process-tree.md) for the parent→child anomaly that often spawns these.
