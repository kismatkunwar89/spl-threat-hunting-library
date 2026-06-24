# 07 - Impact

The attacker's end objective once inside - mass file encryption/destruction over a network
share. Separate from lateral movement: getting onto the share is [05](../05-lateral-movement/);
what they do once there is here.

| Leaf | What it does |
|---|---|
| [ransomware-smb.md](ransomware-smb.md) | Mass file-open/rename storm, or a spike of renames sharing one new extension, over SMB (`bro:smb_files:json`) |

**Related:** [05-lateral-movement/service-based-remote-execution.md](../05-lateral-movement/service-based-remote-execution.md) (how the attacker likely reached the share).
