# Living-off-the-land enumeration binaries

**Use when:** you suspect an attacker is mapping the host or network with native Windows tools
to avoid dropping malware.

## Primary detection - `EventCode 1`
Native tools used to enumerate the environment and find escalation paths.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*\\ipconfig.exe" OR Image="*\\net.exe" OR Image="*\\whoami.exe" OR Image="*\\netstat.exe" OR Image="*\\nbtstat.exe" OR Image="*\\hostname.exe" OR Image="*\\tasklist.exe")
| stats count by Image, CommandLine
| sort - count
```
*Tune: admins run these too - pivot on `ParentImage` to tell a human admin from an automated payload firing them in sequence. Often the parent is the more interesting lead → [90-pivots/process-activity-tree.md](../90-pivots/process-activity-tree.md).*

## Statistical variant - burst detection by parent process
A single recon command is normal admin noise. A *cluster* of distinct recon binaries fired by
the same parent in sequence is what an automated enumeration script looks like. This also
catches the shell-wrapper case (`cmd.exe`/`powershell.exe -c whoami`) that a plain `Image` match
on the binary alone misses.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=1
(Image="*\\arp.exe" OR Image="*\\chcp.exe" OR Image="*\\ipconfig.exe" OR Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\nltest.exe" OR Image="*\\ping.exe" OR Image="*\\systeminfo.exe" OR Image="*\\whoami.exe")
 OR ((Image="*\\cmd.exe" OR Image="*\\powershell.exe") AND (CommandLine="*arp*" OR CommandLine="*chcp*" OR CommandLine="*ipconfig*" OR CommandLine="*net*" OR CommandLine="*nltest*" OR CommandLine="*ping*" OR CommandLine="*systeminfo*" OR CommandLine="*whoami*"))
| fields _time, Image, CommandLine, ParentImage, ParentProcessId, ComputerName, User
| stats values(Image) as Image, dc(Image) as image_count, min(_time) as _time by ParentImage, ParentProcessId, ComputerName, User
| where image_count > 3
```
*`dc(Image)` computes the distinct-binary count in the same `stats` pass that builds the list - no second pass needed. Threshold (`> 3`) is tunable; widen it if legitimate admin scripts chain a few of these together.*

**Related:** [03-execution-injection/abnormal-process-tree.md](../03-execution-injection/abnormal-process-tree.md) for the parent→child anomaly that often spawns these.
