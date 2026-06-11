# Account machine spread

**Use when:** you want to measure how many distinct machines a single account authenticated to
— a single account spanning many hosts suggests lateral spread. (Takes a known `<account>`.)

## Detection — `EventCode 4624` + dc()
```spl
index=* EventCode=4624 Account_Name="<account>"
| stats dc(ComputerName) as distinct_computers
```
*`dc()` deduplicates — many logins to the same box count once. Swap `<account>` for whoever you're chasing.*

**Related:** auth-anomaly siblings in credential access — [04 login-burst-window](../04-credential-access/login-burst-window.md), [04 kerberos-tgt-volume](../04-credential-access/kerberos-tgt-volume.md), [04 dcsync](../04-credential-access/dcsync.md).
