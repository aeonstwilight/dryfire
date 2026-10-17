# <Rule title>

| | |
|---|---|
| **Rule** | [`rules/<platform>/<tactic>/<rule_filename>.yml`](../../rules/<platform>/<tactic>/<rule_filename>.yml) |
| **Rule ID** | `<uuid>` |
| **Level** | <informational / low / medium / high / critical> |
| **ATT&CK** | <Tactic>: <TXXXX.XXX Technique name> |
| **Log source** | <e.g. Sysmon Event ID 10 / Security 4698> |

## Summary

<One or two sentences: what activity this rule flags and why it matters.>

## What it detects

<The logic in plain language: which events, fields and values, and what the
rule deliberately does not cover.>

## Triage steps

1. <First thing to check when it fires.>
2. <Pivot: related process, user, host or network activity to look at.>
3. <What separates malicious from benign here.>
4. <Escalate or close: what evidence supports each outcome.>

## Known false positives

- <Legitimate software or admin activity that can trigger this, and how to recognise it.>

## Related techniques

- <TXXXX.XXX Technique name: why it's related (precursor, follow-on, alternative).>
