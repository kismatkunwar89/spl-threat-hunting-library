# Typosquatted / masquerading binary

**Use when:** you suspect malware hiding behind a misspelled legitimate name (e.g. `psexe.exe`
posing as `PSEXESVC.exe`).

## Detection — `EventCode 1`
Search variants of the suspicious name while excluding the correctly spelled, legitimate binaries.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=1 (CommandLine="*<typo>*" NOT (CommandLine="*<legit1>.exe" OR CommandLine="*<legit2>.exe")) OR (Image="*<typo>*" NOT (Image="*<legit1>.exe" OR Image="*<legit2>.exe"))
| table Image, CommandLine, ParentImage, ParentCommandLine
```
*Tune: the exclusion list is a bypass surface — an attacker can pick a different misspelling. Keep exclusions specific to the real legit binaries only.*

**Related:** [05-lateral-movement/service-based-remote-execution.md](../05-lateral-movement/service-based-remote-execution.md) when the masqueraded tool is a remote-exec utility.
