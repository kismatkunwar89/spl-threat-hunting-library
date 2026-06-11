# 02 - Delivery & Staging

"How did it get on the host?" - delivery, drops, masquerading, and the DNS that precedes a
pull. (A symptom bucket for *getting onto the box*, not strictly MITRE Initial Access.)

| Leaf | What it does |
|---|---|
| [downloads-folder-execution.md](downloads-folder-execution.md) | A process **executed** from a user's Downloads folder (EC1) |
| [suspicious-binary-file-creation.md](suspicious-binary-file-creation.md) | An `.exe`/`.dll` **dropped** outside the Windows dir (EC11) - staging, not proof of execution |
| [typosquat-binary.md](typosquat-binary.md) | A binary masquerading as a legit one via misspelling (EC1) |
| [browser-download-provenance.md](browser-download-provenance.md) | Files tagged internet-origin via `Zone.Identifier` ADS (EC11) |
| [powershell-file-write.md](powershell-file-write.md) | PowerShell writing files to disk (EC11) - staging signal, not itself proof of drive-by |
| [dns-to-trusted-domain.md](dns-to-trusted-domain.md) | A process resolving an allow-listed domain (EC22) - inference of a pull, also a C2 angle |
