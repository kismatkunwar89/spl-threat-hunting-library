# LSASS credential dumping

**Use when:** you're hunting credential theft from LSASS memory - any process that isn't lsass
opening a handle to lsass, and the method it used.

## Primary detection - `EventCode 10` (ProcessAccess)
The behavior: a foreign process accessing lsass.
```spl
index=* EventCode=10 TargetImage="*\\lsass.exe" NOT SourceImage="*\\lsass.exe"
| stats count by ComputerName, SourceImage, GrantedAccess, CallTrace
| sort - count
```
*Sharpen toward dumping: `GrantedAccess="0x1FFFFF"` (full access) and `CallTrace="*UNKNOWN*"` (shellcode from unbacked memory). Group by `SourceImage` - anything absurd (e.g. `notepad.exe`) is the dumper. This is the reliable detector: an attacker can obfuscate the command line but cannot avoid opening the handle.*

## Follow-up enrichment - `EventCode 1` (run only after a hit above)
Name the technique once you have a suspect process - the command line often reveals the method.
```spl
index=* EventCode=1 Image="*\\<process>.exe" CommandLine="*<dll_or_keyword>*"
| table _time, ComputerName, User, CommandLine, ParentImage
| sort _time
```
*This is enrichment, not a standalone detector - command lines can be obfuscated. Constrain `<dll_or_keyword>` to known dump artifacts (e.g. `comsvcs`, `MiniDump`, `mimikatz`).*

**Related:** [03-execution-injection/remote-thread-injection.md](../03-execution-injection/remote-thread-injection.md) (injection that precedes the dump) · [99-detection-engineering/progressive-noise-reduction.md](../99-detection-engineering/progressive-noise-reduction.md) (turn the UNKNOWN call-trace into an alert).
