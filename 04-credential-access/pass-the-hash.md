# Pass-the-Hash

**Use when:** hunting lateral movement via a stolen NTLM hash instead of a plaintext password
(e.g. Mimikatz `sekurlsa::pth`). A Logon Type 9 (NewCredentials) event alone is noisy - normal
admin tooling (`runas`) generates it too. The reliable detection correlates it with the LSASS
access that harvested the hash in the first place.

## Background - what `seclogo` is
`seclogo` (truncated from `seclogon`, the Secondary Logon service) is the mechanism behind
`runas`/`CreateProcessWithLogonW`. It logs Logon Type 9 when a process launches with alternate
credentials. It does not validate the credential immediately - it caches it and only uses it
once the process reaches the network. That's exactly what `sekurlsa::pth` does: spawn a process
via this same mechanism, handing it a stolen hash instead of a password.

## Detection - correlate LSASS access with the alternate-credential logon
Reuses the [lsass-dumping.md](lsass-dumping.md) access-pattern (full access + benign-process
exclusion, not the access mask alone) and stitches it to the Logon Type 9 event on the same host.
```spl
index=* earliest=0
(EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess=0x1fffff
 SourceImage!="*\\Sysmon64.exe" SourceImage!="*\\csrss.exe" SourceImage!="*\\wininit.exe" SourceImage!="*\\msiexec.exe")
 OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=30m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
```
*`maxspan` is a tunable correlation window, not an environment-specific value - check the actual
gap between LSASS access and the following NewCredentials logon in your data before assuming
1 minute. In tested data the gap ran 3 to 21 minutes; 1m missed every real hit. `Network_Account_Domain`/`Network_Account_Name` show the *alternate* (passed) credential, not the
original logged-on user - that's the actual PtH evidence.*

**Related:** [lsass-dumping.md](lsass-dumping.md) for the access-detection half on its own ·
[05-lateral-movement](../05-lateral-movement/) for what the attacker does once the hash is in use.
