# Plaintext credentials in a PsExec command

**Use when:** you want credentials exposed in a PsExec invocation - PsExec takes the password
as an argument, and the whole command line is logged. (This leaf *is* PsExec-named because the
SPL encodes the `*psexec*` artifact.)

## Detection - `EventCode 1`
```spl
index=* EventCode=1 CommandLine="*psexec*"
| table _time, ComputerName, User, CommandLine, ParentImage
| sort _time
```
*The password sits in `CommandLine` in cleartext. `ParentImage` reveals what launched the call - often the dropper. No need to filter on `-p`; pull every psexec invocation and read the line.*

**Related:** [service-based-remote-execution.md](service-based-remote-execution.md) (the service-artifact angles).
