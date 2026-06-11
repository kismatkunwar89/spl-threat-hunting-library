# Rapid DLL loading (malware unpacking)

**Use when:** you suspect a process unpacking itself - loading many unique DLLs in quick
succession to execute a payload.

## Statistical variant - `EventCode 7` + dc()
Count distinct DLLs loaded per process per hour, excluding normal Windows paths, flag the busy ones.
```spl
index=* EventCode=7 NOT (Image="C:\\Windows\\System32*") NOT (Image="C:\\Program Files*") NOT (Image="C:\\ProgramData*") NOT (Image="C:\\Users\\<user>\\AppData*")
| bucket _time span=1h
| stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image
| where unique_dlls_loaded > 3
| stats count by Image, unique_dlls_loaded
| sort - unique_dlls_loaded
```
*Some legitimate installers behave this way - context required. The `> 3` threshold is tunable.*

**Related:** [execute-assembly-clr.md](execute-assembly-clr.md) · [remote-thread-injection.md](remote-thread-injection.md).
