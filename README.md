# SPL Threat-Hunting Library

A reusable, environment-agnostic set of Splunk hunting queries, organized by **what you're
hunting**. Find your scenario below, open that folder, swap the `<placeholders>` for your own
values, and run. Adding queries later? See [CONTRIBUTING.md](CONTRIBUTING.md) and run
[`validate-library.sh`](validate-library.sh).

> Built from my HTB journey — queries I collected and kept track of while working through the
> threat-hunting labs, cleaned up and made reusable so they apply to any environment.

> **Folder numbers group queries for browsing — they are NOT an investigation order.** Real
> hunts jump around. `00–06` are attacker phases; `90` (pivots) and `99` (detection
> engineering) are workflow/meta, deliberately numbered apart so they read as *not* a phase.

---

## What are you hunting? — symptom routing

| If you're seeing / chasing… | Go to |
|---|---|
| A new environment — "what data/indexes/EventCodes exist?" | [00-environment-orientation/](00-environment-orientation/) |
| Native tools (`whoami`, `net`, `ipconfig`) abused for enumeration | [01-host-enumeration/](01-host-enumeration/) |
| Something downloaded/dropped/run from an odd place; a file from the internet; a misspelled binary; DNS to a trusted domain | [02-delivery-staging/](02-delivery-staging/) |
| Code from memory (shellcode); execute-assembly/.NET; thread injection; obfuscated or bursty commands; a weird parent→child like a text editor spawning a shell | [03-execution-injection/](03-execution-injection/) |
| Anything touching `lsass`; DCSync; Kerberos ticket volume; a burst of logins in a tight window | [04-credential-access/](04-credential-access/) |
| PsExec / service-based remote exec; an account reaching many machines | [05-lateral-movement/](05-lateral-movement/) |
| Beaconing; odd outbound ports; data zipped for exfil | [06-c2-exfil/](06-c2-exfil/) |
| You have ONE lead (an IP, a process, an account, a known C2 IP) and need to trace it | [90-pivots/](90-pivots/) |
| Turning a finding into a low-noise alert that survives evasion | [99-detection-engineering/](99-detection-engineering/) |

### Cross-cutting symptoms (live in one home, relevant to several)

| Symptom | Primary home | Also see |
|---|---|---|
| DNS to a trusted/allow-listed domain (payload pull *or* C2) | [02 dns-to-trusted-domain](02-delivery-staging/dns-to-trusted-domain.md) | [06-c2-exfil](06-c2-exfil/) |
| Connections on uncommon ports (C2, lateral transfer, exfil) | [06 uncommon-network-ports](06-c2-exfil/uncommon-network-ports.md) | [05-lateral-movement](05-lateral-movement/) |
| "I have an IP — what is it / who touched it?" | [90 ip-across-sourcetypes](90-pivots/ip-across-sourcetypes.md) | [05 host-interaction](05-lateral-movement/host-interaction.md) |
| **Suspicious account / authentication activity** | spans 04 | [04 login-burst-window](04-credential-access/login-burst-window.md), [04 kerberos-tgt-volume](04-credential-access/kerberos-tgt-volume.md), [04 dcsync](04-credential-access/dcsync.md), [05 account-spread](05-lateral-movement/account-spread.md) |

---

## How to use these

- **Swap placeholders.** Every environment-specific value is a `<token>`: `<index>`, `<host>`,
  `<user>`, `<target_ip>`, `<process>.exe`, `<domain>`, `<seconds>`.
- **Pin your index.** Queries use `index=*` for portability — set your real `index="main"` to
  search faster.
- **Wildcards have no inner spaces.** `"*lsass*"` matches; `" *lsass* "` finds a literal space.
- **Sourcetypes:** Sysmon → `sourcetype="WinEventLog:Sysmon"`, Security →
  `sourcetype="WinEventLog:Security"`.
- **Thresholds are tuning knobs.** Any `k*stdev` or `> N` is a starting point — calibrate.

## EventCode quick map

**Sysmon**

| Code | Meaning |
|---|---|
| 1 | Process creation |
| 3 | Network connection |
| 7 | Image / DLL loaded |
| 8 | CreateRemoteThread (injection) |
| 10 | Process access (handle — lsass, injection) |
| 11 | File create |
| 13 | Registry value set |
| 18 | Named pipe |
| 22 | DNS query |

**Windows Security — authentication & AD**

| Code | Meaning | Used in |
|---|---|---|
| 4624 | Successful logon | login-burst-window (04), account-spread (05) |
| 4662 | AD object access | dcsync (04) |
| 4768 | Kerberos TGT request | kerberos-tgt-volume (04) |

## The two-pillar mindset

Each folder mixes two styles on purpose: **Spot the Known** (precise TTP queries — fast, but
attackers evolve past them) and **Spot the Unusual** (baseline normal, flag deviations —
catches novel behavior). Run both; whichever way an attacker moves, they trip one of them.
