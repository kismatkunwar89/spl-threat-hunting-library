# Obfuscated / abnormally long command line

**Use when:** you're hunting encoded or obfuscated execution — length is a proxy for a hidden
payload.

## Statistical variant — `eval len()`
Compute command-line length and surface the longest, filtering noisy legitimate parents.
```spl
index=* sourcetype="WinEventLog:Sysmon" Image="*cmd.exe" ParentImage!="*msiexec.exe" ParentImage!="*explorer.exe"
| eval len=len(CommandLine)
| table User, len, CommandLine
| sort - len
```
*Reviewing the longest commands quickly exposes heavily encoded operations. Adjust the parent exclusions to your environment's known-noisy installers.*

**Related:** [command-frequency-spike.md](command-frequency-spike.md) (rate anomaly rather than length) · [02-delivery-staging/powershell-file-write.md](../02-delivery-staging/powershell-file-write.md) (download cradles).
