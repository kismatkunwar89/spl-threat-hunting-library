# 06 — Command & Control / Exfiltration

Outbound malicious comms and data theft: beaconing, odd ports, and data staged for exfil.

| Leaf | What it does |
|---|---|
| [beaconing.md](beaconing.md) | Per-process connection-volume spikes — C2 beacon (EC3 + streamstats) |
| [uncommon-network-ports.md](uncommon-network-ports.md) | Connections on non-standard ports (EC3) |
| [archive-exfil.md](archive-exfil.md) | Data compressed into archives before transfer (EC11) |

**Related:** DNS to a trusted domain (C2 over allow-listed infra) →
[02 dns-to-trusted-domain](../02-delivery-staging/dns-to-trusted-domain.md). Finding the port a
C2 used to connect *back in* is a lead-driven pivot →
[90 c2-reentry-port](../90-pivots/c2-reentry-port.md).

> **Split trigger:** when either command-and-control or data-exfiltration grows past ~5–6
> technique files, split this into `06-command-and-control/` + `07-data-exfiltration/`. At
> current size (3 leaves) one folder is correct.
