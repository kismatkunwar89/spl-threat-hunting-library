# Inspect fields & rarity

**Use when:** you know which sourcetypes exist and now need to learn their fields, or want the
least-common data as an anomaly seed.

## Detection

### Summarize the fields in a sourcetype
```spl
sourcetype="<sourcetype>" | fieldsummary
```
*Shows every field, its value distribution, and how often it's populated - fast way to learn an unfamiliar log.*

### Surface the rarest index/sourcetype combinations
```spl
index=* sourcetype=* | rare limit=10 index, sourcetype
```
*Rarity is a signal - the least-common data is often the most interesting.*

**Related:** [enumerate-data.md](enumerate-data.md) for the higher-level inventory.
