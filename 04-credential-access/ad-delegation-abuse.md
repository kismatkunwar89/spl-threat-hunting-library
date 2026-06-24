# AD delegation abuse (unconstrained / constrained)

**Use when:** hunting abuse of Kerberos delegation - unconstrained delegation lets a compromised
server extract the TGT of anyone who connects to it; constrained delegation abuse uses the S4U2self/S4U2proxy extensions to forge a ticket impersonating an admin on a specific allowed
service (`msDS-AllowedToDelegateTo`).

## Discovery phase - PowerShell Script Block Logging (`EventCode 4104`)
Before exploiting delegation, an attacker enumerates which accounts/computers have it enabled.
```spl
index=* source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 (Message="*TrustedForDelegation*" OR Message="*userAccountControl:1.2.840.113556.1.4.803:=524288*" OR Message="*msDS-AllowedToDelegateTo*")
| table _time, ComputerName, EventCode, Message
```
*Requires Script Block Logging enabled. Watch for two bugs in any variant of this query: inner
wildcard spaces (`" *term* "` silently matches nothing) and missing parentheses around the `OR`
chain - without them, `EventCode=4104 Message=A OR Message=B OR Message=C` only scopes the
first condition to `EventCode=4104`; the rest match any event code at all.*

## Execution phase - same port-88 detection as Overpass-the-Hash
Constrained delegation abuse via Rubeus talks directly to the KDC, same as any standalone
ticket-request tool.
```spl
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by ProcessGuid
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
```
See [overpass-the-hash.md](overpass-the-hash.md) for the full breakdown. Look for `s4u`-style
command-line syntax with a `/msdsspn:` target matching what the discovery phase found.

*Unconstrained delegation specifically relies on reusing a stolen TGT, so its execution phase is
detected with standard [pass-the-ticket.md](pass-the-ticket.md) logic instead.*

**Related:** [pass-the-ticket.md](pass-the-ticket.md) · [overpass-the-hash.md](overpass-the-hash.md) · [01-host-enumeration/bloodhound-ldap-enumeration.md](../01-host-enumeration/bloodhound-ldap-enumeration.md) for the broader AD-mapping recon this discovery step is part of.
