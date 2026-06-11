# Contributing to the SPL Library

How to add a query without rotting the structure. Run `./validate-library.sh` before every
commit - it enforces the mechanical rules below; this doc covers the judgment ones.

## Adding a query - the 5 steps

1. **Pick the folder** by attacker phase / intent (see the [README routing table](README.md)).
   Not sure? Use the decision tree below.
2. **Join an existing leaf or make a new one.** Join only if it's the *same behavior, one
   investigation* (the `remote-thread-injection.md` test). Otherwise new leaf.
3. **Name the leaf honestly** (the cardinal rule, below).
4. **Add one line** to that folder's `README.md` index.
5. **Add a top-README symptom row** only if the query introduces a new symptom a hunter would
   search by. Overlap queries get cross-ref links, never a duplicated copy.

## The cardinal rule: filename = narrowest honest claim the SPL supports

A leaf's name must not assert more than its query proves.
- Tool names (`psexec`, `mimikatz`) **only** when the SPL actually encodes that tool's
  artifacts. Generic service/pipe/registry activity → `service-based-remote-execution.md`,
  not `psexec.md`.
- Evidence words (`download`, `dump`, `abuse`) only when the query proves the act. A DNS
  resolution is *inference*, not a payload pull → `dns-to-trusted-domain.md`. A `head 10`
  ticket count is volume, not abuse → `kerberos-tgt-volume.md`.
- When a query only *suggests* malice, say so in the tuning line ("anomaly, not proof").

## The pivots rule: `90-pivots` requires an input lead

A query belongs in `90-pivots` **only if it takes a known lead as input** (`<target_ip>`,
`<account>`, `<process>.exe`, known C2 IPs) and returns context. A lead-free proactive hunt
(e.g. `Account_Name="*"`, `QueryName="*<domain>*"`) is **not** a pivot - file it under its
phase folder. This is why `login-burst-window` lives in `04-credential-access`, not pivots.

## Overlap policy: one primary home + cross-refs

Each query exists as exactly one file in one folder (its primary home). If it's relevant to
other phases, add a **`Related:`** link from those folders' leaves/READMEs and a top-README
symptom row - never copy the SPL. Examples settled by consensus:
- `dns-to-trusted-domain.md` → primary `02-delivery-staging`; cross-ref from C2.
- `uncommon-network-ports.md` → primary `06-c2-exfil`; cross-ref from lateral movement.
- `c2-reentry-port.md` → primary `90-pivots`; cross-ref from `beaconing.md`.

## Leaf template - typed sections

Every leaf opens with a `# Title` and a one-line **Use when**, then one or more typed sections:
- **Primary detection** - the main query, proves the behavior.
- **Follow-up enrichment** - runs only after the primary hits (e.g. lsass EC1 method-id).
- **Statistical variant** - the Spot-the-Unusual counterpart (e.g. EC8 stdev outlier).

End with **Related:** cross-links. Keep wildcards space-free (`"*x*"`, not `" *x* "`) and
every environment value a `<placeholder>`.

## Hard limits (enforced by validator)

- **≤ 4 `` ```spl `` blocks per leaf.** Hit the cap → split into a new leaf (this is the
  anti-accretion guardrail). Forces you through steps 3–4 instead of bolting a 5th query on.
- Every leaf listed exactly once in its folder README.
- No broken relative links. No hardcoded `10.0.0.x` / hostnames / usernames.

## Growth triggers

- **Split `06-c2-exfil`** into `06-command-and-control/` + `07-data-exfiltration/` when either
  side exceeds ~5–6 technique files (renumber pivots/meta only if needed; they're already 90/99).
- A folder with many tiny leaves is fine; a single leaf with many queries is not - judge by
  SPL-block count and distinct intent, not file count.
