# HTTP POST data exfiltration

**Use when:** hunting data smuggled out inside HTTP POST bodies - a stealthy exfil channel since
POST traffic blends in with normal web/form-submission activity.

## Statistical variant - outbound POST byte volume (`bro:http:json` + eventstats)
```spl
index=* sourcetype="bro:http:json" earliest=0 method=POST
| stats sum(request_body_len) as TotalBytes by src, dest, dest_port
| eventstats avg(TotalBytes) as avg, stdev(TotalBytes) as stdev
| eval isOutlier=if(TotalBytes > (avg + 1.5*stdev), 1, 0)
| where isOutlier=1
| eval TotalMB = round(TotalBytes/1024/1024, 2)
| sort - TotalMB
```
*Baselining needs more than one (`src`, `dest`, `dest_port`) population to compare against - if
your environment only has one outbound destination in scope, `avg` collapses to that single
value and `stdev` is 0, so the outlier math can never trigger (a value is never greater than
itself). When that happens, drop the `eventstats`/`isOutlier` layer and just sort on absolute
`TotalMB` instead - a multi-hundred-MB single POST aggregate is self-evidently anomalous without
needing a baseline at all.*

**Related:** [dns-exfiltration.md](dns-exfiltration.md) (a different exfil channel, same
volume-anomaly mindset) · [archive-exfil.md](archive-exfil.md) (the pre-staging step this often
follows).
