# Network port scanning (Nmap-class)

**Use when:** hunting port/host scanning from Zeek connection logs - vertical scans (many ports,
one target) and horizontal scans (one port, many targets) are different breadth axes and need
separate queries.

## Primary detection - vertical scan (`bro:conn:json`, breadth of ports)
One source probing many distinct ports on one or few destinations.
```spl
index=* sourcetype="bro:conn:json" earliest=0
| stats dc(id.resp_p) as distinct_ports by id.orig_h, id.resp_h
| where distinct_ports > <threshold>
| sort - distinct_ports
```

## Statistical variant - horizontal scan (breadth of hosts on one port)
One source touching many destinations on the same port - a sweep rather than a deep probe.
```spl
index=* sourcetype="bro:conn:json" earliest=0
| stats dc(id.resp_h) as distinct_hosts by id.orig_h, id.resp_p
| where distinct_hosts > <threshold>
| sort - distinct_hosts
```

## Follow-up enrichment - corroborate with `conn_state`
A borderline horizontal-scan hit can be real, completed traffic rather than a scan. Check before
calling it confirmed.
```spl
index=* sourcetype="bro:conn:json" earliest=0 id.orig_h=<source_ip> id.resp_p=<port>
| stats count by conn_state
```
*`SF` (successful, normal close) with real bytes transferred means completed connections, not
probing - `S0`/`REJ` (no response/refused) is the actual scan signature. Always run this before
trusting a borderline horizontal-sweep result; a handful of distinct destinations on port 80 is
also what normal web browsing looks like.*

**Related:** [00-environment-orientation/inspect-fields.md](../00-environment-orientation/inspect-fields.md) for unfamiliar Zeek field names · [06-c2-exfil/uncommon-network-ports.md](../06-c2-exfil/uncommon-network-ports.md) for the destination-port-anomaly counterpart.
