# Repeated identical process execution

**Use when:** you're hunting persistence or injection signalled by the same process firing
repeatedly on one host.

## Statistical variant — `transaction` + mvcount
Group process-creation events by host + image; keep only groups with more than one distinct GUID.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=1
| transaction ComputerName, Image
| where mvcount(ProcessGuid) > 1
| stats count by Image, ParentImage
```

## Follow-up enrichment
Extract the command lines of any suspicious pairing it reveals.
```spl
index=* sourcetype="WinEventLog:Sysmon" EventCode=1
| transaction ComputerName, Image
| where mvcount(ProcessGuid) > 1
| search Image="*\\<child>.exe" ParentImage="*\\<parent>.exe"
| table CommandLine, ParentCommandLine
```

**Related:** [command-frequency-spike.md](command-frequency-spike.md) (rate-based view) · [90-pivots/process-activity-tree.md](../90-pivots/process-activity-tree.md).
