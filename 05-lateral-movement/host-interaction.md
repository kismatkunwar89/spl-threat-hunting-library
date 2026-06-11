# Hosts interacting with a known-bad IP

**Use when:** you've identified a staging server or C2 IP and need every host that reached it.
(Takes a known IP as input — a lead-driven query that pairs with the pivots folder.)

## Detection — `EventCode 3`
```spl
index=* <target_ip> sourcetype="WinEventLog:Sysmon"
| stats count by CommandLine, host
```
*Returns the hosts that talked to the IP and what they ran — your victim list and the commands that pulled tooling.*

**Related:** identify *what* the IP is first via [90-pivots/ip-across-sourcetypes.md](../90-pivots/ip-across-sourcetypes.md) · find the inbound port via [90-pivots/c2-reentry-port.md](../90-pivots/c2-reentry-port.md).
