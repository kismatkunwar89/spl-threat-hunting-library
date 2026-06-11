# Enumerate available data

**Use when:** you've just been handed an unfamiliar Splunk environment and need to know what
EventCodes, indexes, sourcetypes, and sources exist before hunting.

## Detection

### List every Event Code present in Sysmon
```spl
index=* sourcetype="WinEventLog:Sysmon" | stats count by EventCode
```
*Tells you which behaviors are actually logged. EventCode 1 (process creation) is usually the richest starting point.*

### List all indexes
```spl
| eventcount summarize=false index=* | table index
```

### List all sourcetypes
```spl
| metadata type=sourcetypes index=* | table sourcetype
```

### List all data sources
```spl
| metadata type=sources index=* | table source
```

**Related:** once you know what exists, drill into fields with [inspect-fields.md](inspect-fields.md), then pick a scenario from the [top README](../README.md).
