# Map a process's activity tree

**Use when:** you have a suspicious process and want everything it spawned and everything that
spawned it.

## Pivot — `EventCode 1`
```spl
index=* Image="*\\<process>.exe" OR ParentImage="*\\<process>.exe"
| stats count by EventCode, Image, ParentImage, CommandLine
```
*Shows both directions at once — its parent (how it got launched) and its children (what it did). Surfaces the full chain around one lead.*

**Related:** confirm which child is the *active* infection → [infection-breadth.md](infection-breadth.md) · [03-execution-injection/abnormal-process-tree.md](../03-execution-injection/abnormal-process-tree.md).
