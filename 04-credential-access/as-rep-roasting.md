# AS-REP roasting

**Use when:** hunting offline cracking attempts against user accounts that have Kerberos
pre-authentication disabled. Normally pre-auth requires proving identity before a TGT is
issued; if disabled, an attacker can request a TGT for that user without the password and
crack the returned hash offline.

## Primary detection - `EventCode 4768` (TGT request), pre-auth disabled
```spl
index=* source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
| stats count, values(Ticket_Encryption_Type) as Ticket_Encryption_Type, min(_time) as _time by user, src_ip
| sort - count
```
*`Pre_Authentication_Type=0` is the definitive signal - this account simply does not require
proof of identity to get a TGT, regardless of who requests it. Aggregating by `user`/`src_ip`
turns a raw event list into a breadth check: a single source enumerating many pre-auth-disabled
accounts in a short window is reconnaissance, not routine use.*

**Tuning notes:** some legitimate service accounts have pre-auth disabled intentionally for
compatibility - cross-reference hits against a known-exception list before alerting. `Ticket_Encryption_Type=0x17` (RC4) on the response raises confidence the hash is easily crackable.

**Related:** [kerberoasting.md](kerberoasting.md) - same offline-cracking goal, different
account type (service vs. user) and different request type (TGS vs. TGT).
