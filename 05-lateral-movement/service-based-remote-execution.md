# Service-based remote execution (PsExec-class)

**Use when:** you're hunting remote command execution via a service install — PsExec, Impacket,
PAExec, and similar. **Not PsExec-exclusive:** these queries detect the generic service /
file / named-pipe artifacts of the technique, which also fire on other tools and some legit
admin activity. Correlate all three angles.

## Detection A — service registry modification — `EventCode 13`
`services.exe` writing a new service `ImagePath`.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath"
| rex field=Details "(?<reg_file_name>[^\\\\]+)$"
| eval reg_file_name=lower(reg_file_name)
| stats values(Image) AS Image, values(Details) AS RegistryDetails, count by reg_file_name, ComputerName
```

## Detection B — service binary file creation — `EventCode 11`
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=11 Image=System
| stats count by TargetFilename
```

## Detection C — named pipe creation — `EventCode 18`
A key fingerprint: the technique communicates over named pipes.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=18 Image=System
| stats count by PipeName
```

**Related:** [psexec-credentials.md](psexec-credentials.md) (the only PsExec-named query — its SPL actually encodes `*psexec*`) · [02-delivery-staging/typosquat-binary.md](../02-delivery-staging/typosquat-binary.md).
