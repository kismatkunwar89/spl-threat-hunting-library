# Zerologon (CVE-2020-1472)

**Use when:** hunting the Netlogon zero-key authentication bypass against a Domain Controller,
via Zeek DCE-RPC logs.

## Primary detection - Netlogon RPC operation volume spike (`bro:dce_rpc:json`)
A hardcoded all-zero AES-CFB8 IV lets an attacker brute-force a zero-key auth bypass via rapid,
repeated `NetrServerReqChallenge`/`NetrServerAuthenticate3` calls, then a single
`NetrServerPasswordSet2` once it succeeds, to blank the DC computer account's password.
```spl
index=* sourcetype="bro:dce_rpc:json" earliest=0 endpoint="netlogon"
| bin _time span=1m
| where operation IN ("NetrServerReqChallenge","NetrServerAuthenticate3","NetrServerPasswordSet2")
| stats count, values(operation) as operation_values, dc(operation) as unique_operations by _time, id.orig_h, id.resp_h
| where unique_operations >= 2 AND count > <threshold>
| sort - count
```
*A volume spike across at least 2 of the 3 operations within a tight window is the brute-force
*attempt* signature on its own - it's already damning, since no legitimate Netlogon traffic
looks like this. But it does not prove the exploit succeeded.*

## Follow-up enrichment - confirm a completed compromise
```spl
index=* sourcetype="bro:dce_rpc:json" earliest=0 endpoint="netlogon" operation="NetrServerPasswordSet2" id.orig_h=<source_ip>
| table _time, id.orig_h, id.resp_h, operation
```
*If this returns nothing for the source that tripped the volume spike, you've confirmed an
attempt, not a successful domain compromise - keep that distinction explicit when reporting it.*

**Related:** [dcsync.md](dcsync.md) and [dcshadow.md](dcshadow.md) (other DC-targeted abuse) ·
[golden-ticket-network.md](golden-ticket-network.md).
