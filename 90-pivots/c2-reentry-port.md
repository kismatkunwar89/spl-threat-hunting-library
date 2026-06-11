# C2 re-entry port (flip the direction)

**Use when:** you've already identified C2 IPs from outbound beaconing and want the port the
attacker used to connect **back into** the network. Requires known C2 IPs as input — this is
follow-up enrichment, not an independent C2 detector.

## Pivot — `EventCode 3` (C2 IP as source)
```spl
index=* EventCode=3 (SourceIp="<c2_ip_1>" OR SourceIp="<c2_ip_2>")
| table _time, ComputerName, SourceIp, SourcePort, DestinationIp, DestinationPort, Image
| sort _time
```
*`DestinationPort` is the port on the victim the attacker reached for. `Image` reveals which service caught it (often gives away the protocol). Always pivot a C2 IP both ways — outbound = beacon, inbound = re-entry/lateral port.*

**Related:** get the C2 IPs first from [06-c2-exfil/beaconing.md](../06-c2-exfil/beaconing.md) · identify the IP via [ip-across-sourcetypes.md](ip-across-sourcetypes.md).
