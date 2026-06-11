# Find the active infection process (EventCode breadth)

**Use when:** a parent spawned several children and you need to know which one is the *active*
infection - not an innocent bystander like an error reporter or shell wrapper.

## Pivot - `dc(EventCode)`
The infection process has breadth: it keeps acting across many event types after spawning.
One-and-done processes show a single EventCode.
```spl
index=* (Image="*\\<process>.exe" OR SourceImage="*\\<process>.exe" OR ParentImage="*\\<process>.exe")
| stats dc(EventCode) as unique_events, values(EventCode) as EventCodes by Image
| sort - unique_events
```
*Highest `dc(EventCode)` = the carrier (network + DLL loads + file writes + registry + injection…). A lone EventCode 1 = spawned and exited, not the infection.*

**Related:** [process-activity-tree.md](process-activity-tree.md) (the full tree around it) · [03-execution-injection/remote-thread-injection.md](../03-execution-injection/remote-thread-injection.md).
