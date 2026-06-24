# Overpass-the-Hash

**Use when:** hunting use of a stolen NTLM hash or AES key to fraudulently request a Kerberos
TGT (e.g. Rubeus `asktgt /rc4:<hash>`), upgrading NTLM-only access into Kerberos. The hash can
come from any credential-theft source (LSASS dump, DCSync, relay capture) - this technique
doesn't require Mimikatz specifically, and Mimikatz alone (`sekurlsa::pth`) can also execute
the whole technique without Rubeus.

## Detection - network connection to the Kerberos port from a non-`lsass` process
Legitimate Kerberos traffic to a Domain Controller originates from `lsass.exe`. A TGT request
crafted by a standalone tool talks directly to port 88 from whatever process is running it,
bypassing `lsass.exe` (and so bypassing the artifacts a standard Pass-the-Hash detection relies
on).
```spl
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by ProcessGuid
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
```
*Join on `ProcessGuid`, not `process_id` - PIDs are recycled and aren't unique across hosts or
time; two unrelated processes can share one. `ProcessGuid` is unique across both.*

**Tuning notes:** if a Mimikatz-based variant is used instead of a standalone tool like Rubeus,
it still goes through `lsass.exe` and leaves the same memory-access artifacts as standard
Pass-the-Hash - see [lsass-dumping.md](lsass-dumping.md) for that half.

**Related:** [pass-the-hash.md](pass-the-hash.md) (NTLM-only variant) · [ad-delegation-abuse.md](ad-delegation-abuse.md) (same port-88 detection, different exploitation path).
