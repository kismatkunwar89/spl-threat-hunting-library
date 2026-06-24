# Service-based remote execution (PsExec-class)

**Use when:** you're hunting remote command execution via a service install - PsExec, Impacket,
PAExec, and similar. **Not PsExec-exclusive:** these queries detect the generic service /
file / named-pipe artifacts of the technique, which also fire on other tools and some legit
admin activity. Correlate all three angles.

## Detection A - service registry modification - `EventCode 13`
`services.exe` writing a new service `ImagePath`.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath"
| rex field=Details "(?<reg_file_name>[^\\\\]+)$"
| eval reg_file_name=lower(reg_file_name)
| stats values(Image) AS Image, values(Details) AS RegistryDetails, count by reg_file_name, ComputerName
```

## Detection B - service binary file creation - `EventCode 11`
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=11 Image=System
| stats count by TargetFilename
```

## Detection C - named pipe creation - `EventCode 18`
A key fingerprint: the technique communicates over named pipes.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=18 Image=System
| stats count by PipeName
```

## Detection D - network payload delivery (Zeek `bro:smb_files:json`)
Complementary to A-C: catches the initial payload transfer to the admin share itself, from the
network side, before any host-level service/registry/pipe artifact exists.
```spl
index=* sourcetype="bro:smb_files:json" earliest=0 action="SMB::FILE_OPEN"
name IN ("*.exe", "*.dll", "*.bat") path IN ("*C$", "*ADMIN$") size>0
| stats count by path, name, id.orig_h, id.resp_h
```
*Match the share-name suffix with a leading wildcard (`"*ADMIN$"`) rather than a literal
backslash (`"*\\ADMIN$"`) - backslash-escaping ambiguity in quoted SPL terms is easy to get
wrong, and the suffix match works regardless of how many backslashes collapse. A randomized,
hex-style filename (vs. a descriptive or versioned name a real deployment tool would use) is
corroborating evidence once you have a hit.*

**Related:** [psexec-credentials.md](psexec-credentials.md) (the only PsExec-named query - its SPL actually encodes `*psexec*`) · [02-delivery-staging/typosquat-binary.md](../02-delivery-staging/typosquat-binary.md).
