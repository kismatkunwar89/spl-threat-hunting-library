# 05 - Lateral Movement

An attacker moving host-to-host: service-based remote execution (PsExec-class), and accounts
reaching across the estate.

| Leaf | What it does |
|---|---|
| [service-based-remote-execution.md](service-based-remote-execution.md) | Service install via registry/file/named-pipe - PsExec-class, not PsExec-exclusive (EC13/11/18) |
| [psexec-credentials.md](psexec-credentials.md) | Plaintext credentials in a PsExec command line (EC1) |
| [host-interaction.md](host-interaction.md) | Which hosts interacted with a known-bad IP (EC3) |
| [account-spread.md](account-spread.md) | Distinct machines a single account authenticated to (EC4624 + dc) |

**Related:** uncommon-port C2/transfer channels used during lateral movement →
[06 uncommon-network-ports](../06-c2-exfil/uncommon-network-ports.md). "I have an IP" →
[90 ip-across-sourcetypes](../90-pivots/ip-across-sourcetypes.md).
