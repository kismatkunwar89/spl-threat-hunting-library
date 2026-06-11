# Network beaconing

**Use when:** you're hunting C2 beacons or exfil — a process whose outbound connection volume
suddenly spikes above its own normal.

## Statistical variant — `EventCode 3` + streamstats
Per-process rolling 24h baseline of hourly connection volume; flag the spikes.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=3
| bin _time span=1h
| stats count as NetworkConnections by _time, Image
| streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image
| eval isOutlier=if(NetworkConnections > (avg + 0.5*stdev), 1, 0)
| search isOutlier=1
```
*The `0.5*stdev` multiplier is sensitive by design — raise it to cut noise. This catches volume anomalies even when C2 hides on port 443.*

**Related:** [uncommon-network-ports.md](uncommon-network-ports.md) (the signature counterpart) · after outbound hits, flip direction to find re-entry → [90-pivots/c2-reentry-port.md](../90-pivots/c2-reentry-port.md).
