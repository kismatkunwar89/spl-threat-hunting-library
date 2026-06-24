# DNS exfiltration

**Use when:** hunting data smuggled out via encoded DNS query subdomains - a channel attackers
favor because DNS is almost always allowed outbound by default.

## Primary detection - long-query volume + distinct-subdomain breadth (`bro:dns:json`)
```spl
index=* sourcetype="bro:dns:json" earliest=0
| eval len_query=len(query)
| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="*amazonaws.com*" AND query!="*._googlecast.*" AND query!="*_ldap.*"
| bin _time span=24h
| stats count(query) as req_by_day, dc(query) as distinct_subdomains by _time, id.orig_h, id.resp_h
| where req_by_day > <threshold>
| sort - req_by_day
```
*Exclude known-long-but-benign domains explicitly (CDN/cloud/multicast-discovery/LDAP/reverse-DNS
infra) - tune this exclusion list to your own environment's normal noise. Keep wildcards
space-free (`"*x*"`, not `" *x* "` - a stray inner space becomes a literal character and
silently breaks the exclusion without erroring).*

`dc(query)` corroborates the raw count: real exfil tooling sends many *distinct* encoded
subdomains (the data chunks being smuggled out), not the same query repeated. A high
distinct-to-total ratio is what separates genuine exfiltration from one long domain resolving
benignly over and over.

**Related:** [02-delivery-staging/dns-to-trusted-domain.md](../02-delivery-staging/dns-to-trusted-domain.md)
(DNS abuse for delivery instead of exfil) · [http-post-exfiltration.md](http-post-exfiltration.md).
