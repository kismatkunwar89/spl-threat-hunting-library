# Golden Ticket - network / orphaned TGS

**Use when:** hunting forged-ticket reuse from Zeek Kerberos logs instead of Windows Security
events - a client presenting TGS requests with no preceding AS-REQ in the dataset.

## Primary detection - `bro:kerberos:json` orphaned TGS request
```spl
index=* sourcetype="bro:kerberos:json" earliest=0
| where client!="-"
| stats values(request_type) as request_types, dc(request_type) as unique_request_types by client, id.orig_h, id.resp_h
| where unique_request_types==1 AND request_types=="TGS"
```
*Group by `client`, not just the IP pair - grouping on the IP pair alone can fold a legitimate
AS-REQ from a different account on the same source machine into the same bucket and mask the
attacker's orphaned request entirely. Check across the full queried time range rather than a
tight bin - a stolen or forged ticket can sit unused far longer than a few minutes before being
presented.*

A client with `request_types=="TGS"` and `unique_request_types==1` across the whole dataset
never performed a real AS-REQ/AS-REP exchange at all - the authentication step was skipped
entirely, which is exactly what presenting a forged or stolen TGT looks like from the network.

**Related:** network-layer counterpart to [golden-silver-ticket.md](golden-silver-ticket.md)'s
Pass-the-Ticket-based detection (same orphaned-ticket logic, different data source) ·
[pass-the-ticket.md](pass-the-ticket.md).
