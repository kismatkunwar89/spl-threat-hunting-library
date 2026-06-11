# Data exfiltration via archive files

**Use when:** you suspect data being staged for theft — compressed into archives before
transfer out of the network.

## Detection — `EventCode 11`
```spl
index=* EventCode=11 (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z")
| stats count by ComputerName, User, TargetFilename
| sort - count
```
*Group by user and host to spot who is bundling data and where. Add other archive extensions (`.tar`, `.gz`, `.cab`) as needed.*

**Related:** the transfer channel → [uncommon-network-ports.md](uncommon-network-ports.md) · [beaconing.md](beaconing.md).
