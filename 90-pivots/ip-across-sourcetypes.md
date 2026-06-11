# Identify an IP across every sourcetype

**Use when:** you have an IP and need to know what it is — Windows host, Linux server, network
device — by seeing where it appears across all data.

## Pivot
```spl
index=* <target_ip> | stats count by sourcetype
```
*If it shows up in `linux:syslog`, it's a Linux box (often an attacker staging server); in Sysmon, a Windows host. Follow up with a scoped search in whichever sourcetype dominates.*

**Related:** find which hosts touched it → [05-lateral-movement/host-interaction.md](../05-lateral-movement/host-interaction.md) · find its inbound port → [c2-reentry-port.md](c2-reentry-port.md).
