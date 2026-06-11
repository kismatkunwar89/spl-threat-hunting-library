# Execution from the Downloads folder

**Use when:** you're chasing "a user ran something they downloaded" — process execution from a
user-writable path, atypical for enterprise software.

## Detection — `EventCode 1`
Proves a process *executed* from a Downloads path (not just dropped there).
```spl
index=* EventCode=1
| regex Image="C:\\\\Users\\\\.*\\\\Downloads\\\\.*"
| stats count by Image
```
*This proves execution. For files merely *dropped* outside the Windows dir (no execution yet), see the sibling leaf.*

**Related:** [suspicious-binary-file-creation.md](suspicious-binary-file-creation.md) (drop, not execution) · trace what ran via [90-pivots/process-activity-tree.md](../90-pivots/process-activity-tree.md).
