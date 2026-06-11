# Suspicious binary file creation

**Use when:** you're chasing a payload **dropped** to disk — an `.exe` or `.dll` created
outside the protected Windows directories. This proves a *drop*, not execution.

## Detection — `EventCode 11`
Legit system binaries live in protected folders; malware often drops elsewhere (Downloads,
AppData, ProgramData, Temp).
```spl
index=* EventCode=11 (TargetFilename="*.exe" OR TargetFilename="*.dll") TargetFilename!="*\\windows\\*"
| stats count by User, TargetFilename
| sort + count
```
*This is a staging signal — the file exists, but creation ≠ execution. Pair with execution evidence.*

**Related:** [downloads-folder-execution.md](downloads-folder-execution.md) (proves the run) · [03-execution-injection/](../03-execution-injection/) if the drop was injected rather than written.
