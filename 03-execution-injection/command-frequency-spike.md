# Command-execution frequency spike

**Use when:** the command itself looks benign but the *rate* is abnormal — a burst of
executions can mean an automated malicious script.

## Statistical variant — `EventCode 1` + eventstats
Bucket executions hourly, baseline per-hour average/stdev, flag spikes.
```spl
index=* EventCode=1 CommandLine="*cmd.exe*"
| bucket _time span=1h
| stats count as cmdCount by _time, User, CommandLine
| eventstats avg(cmdCount) as avg stdev(cmdCount) as stdev
| eval isOutlier=if(cmdCount > avg + 1.5*stdev, 1, 0)
| search isOutlier=1
```
*The `1.5*stdev` multiplier is the sensitivity knob — raise it to quiet noisy environments.*

**Related:** [obfuscated-long-command.md](obfuscated-long-command.md) (length anomaly) · [repeated-process-execution.md](repeated-process-execution.md) (same process, repeated).
