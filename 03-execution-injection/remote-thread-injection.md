# Remote thread injection (CreateRemoteThread)

**Use when:** you're hunting one process creating a thread inside another's memory - classic
process injection. Includes both a direct hunt and a population outlier (the model pattern for
pairing Spot-the-Known with Spot-the-Unusual in one leaf).

## Primary detection - `EventCode 8`
Direct hunt: who injected into a specific victim process.
```spl
index=* EventCode=8 TargetImage="*\\<victim>.exe"
| stats count by ComputerName, SourceImage, TargetImage, User
| sort - count
```
*`SourceImage` is the injector; `TargetImage` is the hijacked host process.*

## Statistical variant - `EventCode 8` + eventstats
When you *don't* know the victim, let the data name the injector: flag any source process
injecting more than 2 standard deviations above the mean.
```spl
index=* EventCode=8
| stats count as threads_created by SourceImage
| eventstats avg(threads_created) as avg stdev(threads_created) as stdev
| eval threshold = avg + 2*stdev
| where threads_created > threshold
| table SourceImage, threads_created, avg, stdev, threshold
| sort - threads_created
```
*Exclude known AV/EDR injectors before the baseline or they drag the average up and mask the real outlier. The `2*stdev` is a tuning knob.*

**Related:** [execute-assembly-clr.md](../03-execution-injection/execute-assembly-clr.md) · confirm the injected process is the *active* infection via [90-pivots/infection-breadth.md](../90-pivots/infection-breadth.md).
