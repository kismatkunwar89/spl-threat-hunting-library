# Abnormal parent → child process tree

**Use when:** you've spotted (or want to find) an illogical process hierarchy - a text editor
spawning a shell, a document app launching `powershell.exe`.

## Detection - `EventCode 1`
Surface unexpected parent→child pairings for shell processes.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*\\cmd.exe" OR Image="*\\powershell.exe")
| stats count by ParentImage, Image
```

## Follow-up enrichment - `EventCode 1`
Drill into the suspicious pair to read the actual command.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*\\cmd.exe" OR Image="*\\powershell.exe") ParentImage="*\\<parent>.exe"
```
*This is where you'll often catch a download cradle (e.g. `Invoke-WebRequest`) pulling the next stage. Take any IP/domain you find and pivot.*

**Related:** [01-host-enumeration/lolbin-recon.md](../01-host-enumeration/lolbin-recon.md) (what the spawned shell then runs) · [90-pivots/ip-across-sourcetypes.md](../90-pivots/ip-across-sourcetypes.md) (chase a cradle's IP).
