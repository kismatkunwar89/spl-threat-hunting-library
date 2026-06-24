# Kerberoasting

**Use when:** hunting offline cracking attempts against AD service accounts via Kerberos
service ticket requests.

## Primary detection - `EventCode 4769` (Kerberos service ticket request), RC4 encryption
Roasting tools (Rubeus, Impacket) request RC4 (`0x17`) by default because RC4 hashes crack far
faster offline than AES. A well-configured environment using AES-capable/gMSA service accounts
rarely sees RC4 requested legitimately, making it a durable standalone signal independent of any
specific service name.
```spl
index=* source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type=0x17 service_name!="krbtgt" service_name!="*$"
| stats count, values(Ticket_Encryption_Type) as Ticket_Encryption_Type, min(_time) as _time by user, service_name
| sort - count
```
*Do not scope this to one known service name (`service_name=<specific_account>`) - Kerberoasting
targets any service account with an SPN, and hardcoding the name misses every other target.
Read the sorted output for a cliff: legitimate service tickets sit in single digits, an actual
roasting run shows hundreds to thousands against one account. Corroborate with breadth (multiple
distinct users requesting the same service) and origin (a known-rogue domain requesting it).*

## Follow-up enrichment - network detection (Zeek `bro:kerberos:json`)
Same attack, detected from raw Kerberos network traffic instead of Windows Security logs - RC4
alone isn't rare enough to act on, so add the same volume/breadth layer used above.
```spl
index=* sourcetype="bro:kerberos:json" earliest=0 request_type=TGS cipher="rc4-hmac" forwardable="true" renewable="true"
| stats count, dc(service) as distinct_services, values(service) as services by client, id.orig_h, id.resp_h
| sort - count
```
*Don't assume the anomaly will be breadth (one account hitting many services) - check for
burst-repetition too (one account requesting the same single service many times within a
second or two). No normal Windows client re-requests an identical ticket that fast; burst
repetition against one target is just as real a signal as breadth across many.*

**Related:** [kerberos-tgt-volume.md](kerberos-tgt-volume.md) for the TGT-request-volume
sibling check · [dcsync.md](dcsync.md) for the AD-replication abuse this often precedes.
