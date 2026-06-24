# Network beaconing

**Use when:** you're hunting C2 beacons or exfil - a process whose outbound connection volume
suddenly spikes above its own normal.

## Statistical variant - `EventCode 3` + streamstats
Per-process rolling 24h baseline of hourly connection volume; flag the spikes.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=3
| bin _time span=1h
| stats count as NetworkConnections by _time, Image
| streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image
| eval isOutlier=if(NetworkConnections > (avg + 0.5*stdev), 1, 0)
| search isOutlier=1
```
*The `0.5*stdev` multiplier is sensitive by design - raise it to cut noise. This catches volume anomalies even when C2 hides on port 443.*

## Follow-up enrichment - network timing-jitter (Zeek `bro:http:json`)
A different signal than connection-volume spikes: beacons check in at a regular interval with
small jitter, so the time *between* connections clusters tightly even though the absolute
volume may look unremarkable.
```spl
index=* sourcetype="bro:http:json" earliest=0
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
| eval upper=avg*1.1
| eval lower=avg*0.9
| where timedelta > lower AND timedelta < upper
| stats count, values(avg) as TimeInterval by src, dest, dest_port, total
| eval prcnt = (count/total)*100
| where prcnt > 90 AND total > 10
```
*The `*1.1`/`*0.9` margin mathematically counters jitter - it builds a 10% band around the
average interval and checks what fraction of connections land inside it. `prcnt > 90 AND
total > 10` requires both consistency and enough history to trust the pattern.*

**Related:** [uncommon-network-ports.md](uncommon-network-ports.md) (the signature counterpart) · after outbound hits, flip direction to find re-entry → [90-pivots/c2-reentry-port.md](../90-pivots/c2-reentry-port.md).
