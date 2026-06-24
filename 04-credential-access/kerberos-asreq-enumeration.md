# Kerberos AS-REQ brute force / username enumeration (network)

**Use when:** hunting a high volume of failed AS-REQ requests from Zeek Kerberos logs - distinct
from [kerberos-tgt-volume.md](kerberos-tgt-volume.md), which flags high *successful* TGT
volume rather than failed enumeration attempts.

## Primary detection - `bro:kerberos:json` failed AS-REQ volume + username breadth
```spl
index=* sourcetype="bro:kerberos:json" earliest=0 error_msg!=KDC_ERR_PREAUTH_REQUIRED success="false" request_type=AS
| bin _time span=5m
| stats count, dc(client) as unique_usernames, values(error_msg) as error_messages by _time, id.orig_h, id.resp_h
| where count > <threshold>
| sort - count
```
*Excludes `KDC_ERR_PREAUTH_REQUIRED` - the standard response to a request against a real
username - to isolate genuine `KDC_ERR_C_PRINCIPAL_UNKNOWN` rejections (no `KRB5` prefix in the
raw Zeek field, despite how it's commonly written in documentation - verify against your own
data before trusting either form). When `count` matches `unique_usernames` exactly (no repeats)
and every attempt fails identically, that's a clean enumeration sweep through many usernames,
not repeated guessing against one account.*

**Related:** [rdp-bruteforce.md](rdp-bruteforce.md) (same guessing-vs-enumeration distinction,
different protocol) · [kerberos-tgt-volume.md](kerberos-tgt-volume.md) (the successful-volume
sibling check) · [golden-ticket-network.md](golden-ticket-network.md).
