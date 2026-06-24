# 01 - Host Enumeration

Post-compromise enumeration of the host/network using native tooling. (Named "host
enumeration," not "recon" - this is on-box discovery behavior, not pre-attack reconnaissance.)

| Leaf | What it does |
|---|---|
| [lolbin-recon.md](lolbin-recon.md) | Native living-off-the-land binaries used to map the host/network |
| [bloodhound-ldap-enumeration.md](bloodhound-ldap-enumeration.md) | BloodHound/SharpHound AD relationship mapping via LDAP-Client ETW telemetry |
| [network-port-scanning.md](network-port-scanning.md) | Vertical and horizontal Nmap-class scanning, plus `conn_state` corroboration (Zeek `bro:conn:json`) |

**Related:** an illogical parent→child (text editor spawning a shell) is execution behavior -
see [03-execution-injection/abnormal-process-tree.md](../03-execution-injection/abnormal-process-tree.md).
