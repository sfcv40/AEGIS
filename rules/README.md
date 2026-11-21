# AEGIS detection rules

| Folder | Format | Consumed by |
|--------|--------|-------------|
| `yara/` | YARA 4.x | File scans (A6, A7 follow-ups) and memory scans of suspicious processes (B1, and the script-host scan in `behavior/`) |
| `behavior/` | AEGIS behaviour rules (YAML, schema below) | The live engine: handle sampler (A1), ETW consumer (A2), window and input checks (B3, B4), artifact sweeps (A6) |
| `sigma/` | Sigma | Windows event log sources AEGIS reads at session start (PowerShell 4104, Security 4688 / Sysmon 1) |

`behavior/aegis-core.yaml` holds the family-agnostic Tier 1 rules (A2 to A6, YARA, self-protection).
`aegis.exe` embeds every file here at build time. Sigma rules are reported as `SIGMA-<sigma id>`.
Behaviour rule metadata (title, severity, confidence, roadmap, families, correlate) is read
from the YAML; the `match:` blocks document what the detector in `src/win/` implements.

Run the YARA test against local samples (samples are never committed):

```
pip install yara-python
python -I tests/test_yara_rules.py <folder-with-samples>
```

## Behaviour rule schema

```yaml
id: AEGIS-<FAMILY|GEN>-<NNN>   # stable, never reused
title: short sentence
roadmap: [A1, B3]            # roadmap signals the rule belongs to
families: [Destiny]          # cheats it was written against; [generic] if not family-specific
severity: low | medium | high | critical
confidence: low | medium | high
source: handle | etw.process | etw.audit_api | etw.image | etw.dotnet | window | input | file | registry | named_object | network | dns | memory
match: { ... }               # source-specific fields, all conditions ANDed
correlate: [rule ids]        # optional: rules that raise confidence when they fire in the same session
false_positives: [ ... ]
notes: free text
```

Rules emit evidence, not bans (roadmap ground rule 4). Severity says how bad it is if
true; confidence says how likely it is true on its own.
