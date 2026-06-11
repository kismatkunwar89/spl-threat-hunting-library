# Kerberos TGT request volume

**Use when:** you want accounts requesting an unusual number of Kerberos ticket-granting
tickets. High volume is an *indicator* to investigate — a `head 10` ranking is not proof of
abuse on its own.

## Detection — `EventCode 4768` (Security)
```spl
index=* EventCode=4768
| stats count as ticket_requests by Account_Name
| sort - ticket_requests
| head 10
```
*The account at the top has the most TGT requests — context decides whether that's abuse (e.g. ticket harvesting) or a busy service account.*

**Related:** [dcsync.md](dcsync.md) · [login-burst-window.md](login-burst-window.md) · [05-lateral-movement/account-spread.md](../05-lateral-movement/account-spread.md).
