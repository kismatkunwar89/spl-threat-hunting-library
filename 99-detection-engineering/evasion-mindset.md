# The evasion mindset

**Use when:** building or reviewing any alert. Every exclusion you add is a bypass an attacker
can use — design with that in mind.

## Principle

Each string exclusion is a hole. Filtering out `*ni.dll*` to silence .NET noise means an
attacker can slip past by naming a payload `...ni.dll` or appending `NI` to a DLL. Same for any
path or process-name exclusion.

Guidelines:
- Make exclusions **as specific as defensible** — exact paths and known-good binaries, not
  broad substrings.
- Prefer excluding on **stable, attacker-uncontrolled** fields over attacker-chosen strings
  (filenames, command-line text).
- Treat detection as **iteration**, not a one-time rule — revisit exclusions as TTPs evolve.
- Pair every signature (**Spot the Known**) with a statistical net (**Spot the Unusual**) so a
  single bypassed rule doesn't blind you.

**Related:** applied in [progressive-noise-reduction.md](progressive-noise-reduction.md).
