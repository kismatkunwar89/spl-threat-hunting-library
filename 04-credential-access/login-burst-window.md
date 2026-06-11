# Login burst within a tight window

**Use when:** you want accounts whose **entire** login history fits inside a short window — a
burst rather than steady normal activity. This is a lead-free population hunt (`Account_Name="*"`),
so it lives under credential access, not pivots. An anomaly here is an *indicator*, not proof
of compromise.

## Statistical variant — `EventCode 4624` + range()
```spl
index=* EventCode=4624 Account_Name="*"
| search NOT Account_Name="*$*"
| stats count AS logins, range(_time) AS span by Account_Name
| where span < <seconds>
| sort - logins
```
*`range(_time)` = seconds between first and last login per account. `NOT *$*` drops machine accounts. Single-login accounts have `span=0` and always pass — review separately. Set `<seconds>` to your window (e.g. `600` for 10 minutes).*

**Related:** [kerberos-tgt-volume.md](kerberos-tgt-volume.md) (same auth-hunting class) · [05-lateral-movement/account-spread.md](../05-lateral-movement/account-spread.md) (where those logins landed).
