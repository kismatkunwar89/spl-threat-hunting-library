# 03 - Execution & Injection

Code running from memory rather than disk, plus the process-behavior anomalies that betray it:
shellcode, execute-assembly, thread injection, and obfuscated/bursty command activity.

| Leaf | What it does |
|---|---|
| [abnormal-process-tree.md](abnormal-process-tree.md) | Illogical parent→child (e.g. text editor spawning a shell) (EC1) |
| [execute-assembly-clr.md](execute-assembly-clr.md) | Unmanaged process loading the .NET runtime `clr.dll` (EC7) |
| [remote-thread-injection.md](remote-thread-injection.md) | CreateRemoteThread injection - direct hunt + statistical outlier (EC8) |
| [obfuscated-long-command.md](obfuscated-long-command.md) | Abnormally long / encoded command lines (`eval len`) |
| [command-frequency-spike.md](command-frequency-spike.md) | Bursts of command execution above baseline (EC1 + eventstats) |
| [rapid-dll-loading.md](rapid-dll-loading.md) | A process loading many unique DLLs fast - unpacking (EC7 + dc) |
| [repeated-process-execution.md](repeated-process-execution.md) | Same process firing repeatedly - persistence/injection (transaction) |
