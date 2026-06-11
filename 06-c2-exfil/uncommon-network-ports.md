# Uncommon network ports

**Use when:** you're looking for tool transfer or C2 over non-standard ports. This query is
direction- and tactic-agnostic — equally relevant to C2, lateral transfer, and odd exfil
channels.

## Detection — `EventCode 3`
Exclude the noisy standard web/transfer ports to expose what's left.
```spl
index=* EventCode=3 NOT (DestinationPort=80 OR DestinationPort=443 OR DestinationPort=22 OR DestinationPort=21)
| stats count by SourceIp, DestinationIp, DestinationPort
| sort - count
```
*Blind spot: sophisticated C2 hides on 443/80 and this will miss it — always pair with [beaconing.md](beaconing.md). The port exclusion list is a heuristic, not a guarantee.*

**Related:** also a lateral-movement channel → [05-lateral-movement/](../05-lateral-movement/) · [beaconing.md](beaconing.md) for the volume-based catch.
