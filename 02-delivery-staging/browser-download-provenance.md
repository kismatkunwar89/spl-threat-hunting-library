# Browser download provenance (Zone.Identifier)

**Use when:** you want files that came **from the internet via a browser** - Windows tags
internet-sourced files with a `Zone.Identifier` Alternate Data Stream.

## Detection - `EventCode 11`
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*<browser>.exe" TargetFilename="*Zone.Identifier"
| stats count by TargetFilename
| sort + count
```
*`Zone.Identifier` is genuine browser-origin evidence - distinct from a process merely writing a file.*

**Related:** [powershell-file-write.md](powershell-file-write.md) for the scripted-download angle · [suspicious-binary-file-creation.md](suspicious-binary-file-creation.md) for drops without provenance.
