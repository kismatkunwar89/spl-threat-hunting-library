# PowerShell file write

**Use when:** you're looking for PowerShell dropping files to disk - a staging signal. Note: a
file write alone is **not** proof of a drive-by download (PowerShell also writes files for
staging, exfil prep, lateral tooling, and legit admin scripts).

## Detection - `EventCode 11`
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*powershell.exe*"
| stats count by Image, TargetFilename
| sort + count
```
*Inference, not proof - corroborate with provenance (Zone.Identifier) or a download cradle in the command line.*

**Related:** [browser-download-provenance.md](browser-download-provenance.md) for internet-origin proof · [03-execution-injection/obfuscated-long-command.md](../03-execution-injection/obfuscated-long-command.md) for the cradle itself.
