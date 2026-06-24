# Ransomware over SMB

**Use when:** hunting mass file encryption/destruction over a network share via Zeek SMB file
logs. Two distinct SMB-level approaches, each with its own signature.

## Primary detection - overwrite approach (`SMB::FILE_OPEN` + `SMB::FILE_RENAME` volume)
Ransomware that encrypts in memory and overwrites the original file leaves fewer artifacts, but
the open+rename pair repeats rapidly across many files from one source.
```spl
index=* sourcetype="bro:smb_files:json" earliest=0
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_RENAME")
| bin _time span=5m
| stats count by _time, id.orig_h, action
| where count > <per_action_threshold>
| stats sum(count) as count, values(action) as action_values, dc(action) as uniq_actions by _time, id.orig_h
| where uniq_actions==2 AND count > <total_threshold>
```

## Statistical variant - renaming approach (shared new extension)
Ransomware that appends a lock extension (`.lock`, `.crypt`, a random string) on rename - a
spike of files all landing on the exact same new extension is the tell.
```spl
index=* sourcetype="bro:smb_files:json" earliest=0 action="SMB::FILE_RENAME"
| bin _time span=5m
| rex field="name" "\.(?<new_file_name_extension>[^\.]*)$"
| rex field="prev_name" "\.(?<old_file_name_extension>[^\.]*)$"
| stats count by _time, id.orig_h, id.resp_h, name, old_file_name_extension, new_file_name_extension
| where new_file_name_extension!=old_file_name_extension
| stats count by _time, id.orig_h, id.resp_h, new_file_name_extension
| where count > <threshold>
| sort - count
```
*Group by `id.orig_h`/`id.resp_h`, not a generic `source` field - Splunk's `source` is reserved
metadata (the ingested file path), not an attacker-IP field, and grouping by it silently
collapses every source into one bucket instead of erroring. SMB traffic is virtually always
port 445, so grouping by destination port instead of destination host adds no discriminating
value - verify your real field names via `transpose` before trusting either.*

**Related:** [05-lateral-movement/service-based-remote-execution.md](../05-lateral-movement/service-based-remote-execution.md) (how the attacker likely reached the share in the first place).
