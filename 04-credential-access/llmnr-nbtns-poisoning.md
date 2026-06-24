# LLMNR/NBT-NS poisoning (Responder-style relay)

**Use when:** you suspect an attacker is running Responder or a similar tool, answering
broadcast name-resolution queries for mistyped/non-existent hostnames to capture or relay
NetNTLM auth. Two independent telemetry layers - use either, ideally both.

## Primary detection - Sysmon EventCode 22 (the resolution mechanism itself)
LLMNR/NBT-NS only ever activates as a fallback when standard DNS fails to resolve a name -
and DNS only fails that way for bare, single-label hostnames (no domain suffix). A legitimate,
unregistered single-label name should return nothing. A query that got an answer anyway is the
tell - something other than real DNS responded.
```spl
index=* EventCode=22 QueryName!="*.*" QueryResults!=""
| table _time, Computer, User, Image, QueryName, QueryResults
| stats count by QueryName, QueryResults
| sort - count
```

## Statistical variant - Security EventCode 4648, domain-suffix allowlist
A breadth-based check (one source authenticating to many distinct target names) needs volume
to work - in practice a single relay hit may be the only event in the window, so there's
nothing to threshold against. The signal that holds regardless of volume: every legitimate
`Target_Server_Name` belongs to the real domain or is a known short name/machine account. The
rogue one doesn't.
```spl
index=* EventCode=4648
| eval host_label=lower(mvindex(split(Target_Server_Name, "."), 0))
| eval is_trusted_fqdn=if(match(Target_Server_Name, "(?i)\.<your_domain>\.local$"), 1, 0)
| eventstats values(eval(if(is_trusted_fqdn=1, host_label, null()))) as trusted_labels
| where NOT match(Target_Server_Name, "\$$") AND host_label!="localhost"
| where is_trusted_fqdn=0 AND isnull(mvfind(trusted_labels, "^".host_label."$"))
| stats count, values(Network_Address) as Network_Address, values(user) as user, values(Message) as Message by Target_Server_Name
```
*Dynamically derives trusted short names from the data itself (`DC01` is recognized as trusted
because `DC01.<your_domain>.local` already appears under the real domain) instead of
hardcoding a name list - survives new servers being added without retuning.*

**Confirming a hit, not just flagging it:** check the full event text for two tells -
- A `Network_Address` that's **link-local IPv6** (`fe80::...`) - that's the actual protocol
  signature of LLMNR/NBT-NS, which operates over link-local multicast, not routed DNS.
- SPNs in `Additional Information` like `LDAP/...`, `cifs/...` against an off-domain target -
  classic NTLM relay (Responder + ntlmrelayx pattern), not just poisoning in isolation.

**Tuning notes:**
- Allowlisting surfaces *candidates*, not confirmed attacks - a legitimately named workstation
  (e.g. named after an employee) with a local, on-domain logon and no relay SPN pattern is
  almost certainly noise. Don't auto-alert on the allowlist miss alone; check the evidence above
  before escalating.
- Multi-domain/trust environments will need the regex extended to match every trusted suffix,
  not just one, or this fires constantly.

**Related:** [01-host-enumeration/lolbin-recon.md](../01-host-enumeration/lolbin-recon.md) for
native-command recon that often precedes a relay attempt once the attacker has a foothold.
