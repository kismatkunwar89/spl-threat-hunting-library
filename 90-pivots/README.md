# 90 - Investigation Pivots

**Not a kill-chain phase.** These are mid-hunt techniques that **take a known lead as input**
(an IP, a process, an account, a known C2 IP) and widen the picture. If a query takes no lead
and hunts broadly, it belongs in a phase folder, not here.

| Leaf | What it does |
|---|---|
| [ip-across-sourcetypes.md](ip-across-sourcetypes.md) | Identify what an IP is by pivoting it across every sourcetype |
| [process-activity-tree.md](process-activity-tree.md) | Map everything a process spawned and was spawned by (EC1) |
| [infection-breadth.md](infection-breadth.md) | Find the *active* infection process via EventCode breadth (dc) |
| [c2-reentry-port.md](c2-reentry-port.md) | The port a known C2 IP used to connect back in (EC3, flipped) |
