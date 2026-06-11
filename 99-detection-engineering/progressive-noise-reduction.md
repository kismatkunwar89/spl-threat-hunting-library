# Progressive noise reduction

**Use when:** a raw hunt fires too often to alert on (e.g. `CallTrace="*UNKNOWN*"` triggers
thousands of times). Filter step-by-step, watching the count drop, until only signal remains.

## Technique — layer exclusions one at a time

**Step 1 — drop self-access** (a process accessing itself)
```spl
index=* CallTrace="*UNKNOWN*" | where SourceImage!=TargetImage | stats count by SourceImage
```
**Step 2 — drop .NET / JIT compilers** (legitimately use unbacked memory)
```spl
index=* CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!="*ni.dll*" CallTrace!="*clr.dll*" | where SourceImage!=TargetImage | stats count by SourceImage
```
**Step 3 — drop WOW64** (Heaven's Gate triggers this legitimately)
```spl
index=* CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!="*ni.dll*" CallTrace!="*clr.dll*" CallTrace!="*wow64*" | where SourceImage!=TargetImage | stats count by SourceImage
```
**Step 4 — drop noisy Explorer**, then display survivors with context
```spl
index=* CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!="*ni.dll*" CallTrace!="*clr.dll*" CallTrace!="*wow64*" SourceImage!="C:\\Windows\\Explorer.EXE" | where SourceImage!=TargetImage | stats count by SourceImage, TargetImage, CallTrace
```

**Related:** the detection this hardens → [04-credential-access/lsass-dumping.md](../04-credential-access/lsass-dumping.md) and [03-execution-injection/execute-assembly-clr.md](../03-execution-injection/execute-assembly-clr.md) · the mindset behind it → [evasion-mindset.md](evasion-mindset.md).
