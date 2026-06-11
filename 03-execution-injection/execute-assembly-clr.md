# Execute-assembly / C# injection (clr.dll load)

**Use when:** you're hunting in-memory .NET execution - a process loading the CLR with no
legitimate reason to run managed code.

## Detection - `EventCode 7`
Unmanaged processes have no reason to load the .NET runtime.
```spl
index=* EventCode=7 ImageLoaded="*\\clr.dll"
| stats count by ComputerName, Image, User
| sort - count
```
*Review `Image` for processes that should never run .NET (e.g. `notepad.exe`, `rundll32.exe`). Note: `clr.dll` also appears in legitimate JIT - this generates false positives, which is exactly why the alert-hardening filters exist.*

**Related:** [remote-thread-injection.md](remote-thread-injection.md) (the injection that often precedes it) · [99-detection-engineering/progressive-noise-reduction.md](../99-detection-engineering/progressive-noise-reduction.md) (filtering JIT noise).
