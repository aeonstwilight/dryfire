# CLAUDE.md

Guidance for Claude Code working in this repo.

## What this project is

A detection-as-code portfolio repo for a SOC analyst / detection engineer. Sigma rules are the single source of truth; CI lints them, converts them to Splunk SPL and Microsoft Sentinel/Defender KQL, tests them against public attack datasets, and builds an ATT&CK Navigator coverage layer. See README.md for the layout and roadmap.

## Who you're working with

- The owner has deep SOC, detection and incident response experience and knows Splunk SPL, KQL (Elastic and Kusto), Sysmon and Windows event logs well. Don't explain detection concepts.
- Their Python is limited. When you write or change code, explain what it does and why in plain language, keep it simple and readable over clever, and avoid unnecessary abstractions or dependencies.
- The owner decides the detection logic, rule scope and guardrails. Propose rule logic, but don't add, remove or change rules without asking.

## Hard rules

- **All rules are original.** Do not copy rules from SigmaHQ or anywhere else. If the owner explicitly chooses to adapt a SigmaHQ rule, credit it in `author` and `references` (Detection Rule License requires attribution).
- **No employer material.** Never reproduce detections, queries, field names, hostnames, or anything else from the owner's former employers. If something looks like it came from a work environment, stop and ask.
- **No secrets or real environment data** in the repo. Test data comes only from public datasets (EVTX-ATTACK-SAMPLES, OTRF Security Datasets) or is synthetic.
- **Check current versions.** Verify package names, CLI flags and backend/pipeline names (pySigma, sigma-cli, pySigma-backend-splunk, pySigma-backend-kusto, Zircolite) against their current docs before using them. Don't rely on memory.

## Conventions

- Rule path: `rules/<platform>/<tactic>/<platform>_<short_description>.yml`
- Every rule needs: a UUID `id`, `title`, `status`, `description`, `author`, `date`, ATT&CK tags (`attack.<tactic>`, `attack.tXXXX[.XXX]`), `logsource`, `detection`, `falsepositives`, `level`, `references`.
- Every rule needs a matching test case in `tests/cases/<rule_filename>.yml` with:
  - `rule`: path to the rule
  - `positive`: sample file(s) and minimum expected hit count
  - `negative`: benign sample file(s) where the expected hit count is 0
- Every rule needs a triage note in `docs/rules/<rule_filename>.md` using `docs/rules/_template.md`. The template has these sections:
  - Summary
  - What it detects
  - Triage steps
  - Known false positives
  - Related techniques
- `build/` is generated and gitignored. Never hand-edit it.
- Keep large datasets out of git; `scripts/fetch_datasets.py` downloads them into `tests/data/external/` (gitignored). Only small, trimmed samples are checked in.

## Commands

The Makefile should expose these targets:

- `make lint`: `sigma check` on all rules
- `make convert`: SPL and KQL into `build/`
- `make test`: run `tests/run_tests.py`; non-zero exit on any failure
- `make coverage`: write `build/coverage/layer.json`
- `make all`: all of the above, in order

CI (`.github/workflows/ci.yml`) runs `make all` on push and pull request and uploads `build/` as an artifact.

## Milestone 1 (current)

Milestone 1 is done when pushing a rule makes CI report pass or fail on lint, convert, test and coverage.

**Build order:**

1. Scaffold the layout, `requirements.txt`, Makefile, `.gitignore` and the triage-note template.
2. Write `scripts/convert.py`, `scripts/coverage.py`, `scripts/fetch_datasets.py` and `tests/run_tests.py`.
3. Write the CI workflow.
4. Add rules one at a time. For each rule, add the rule, its test case and its triage note, and confirm the rule passes before starting the next.

**Starter rules:** the owner will confirm the logic for each.

1. LSASS memory access (Sysmon 10)
2. Encoded or obfuscated PowerShell command line
3. Scheduled task created (Security 4698)
4. New service installed (System 7045)
5. Security event log cleared (Security 1102)
6. certutil used to download files
7. Office application spawning cmd or PowerShell
8. WMI (wmiprvse) spawning a suspicious child process
9. User added to local Administrators (Security 4732)
10. Suspicious rundll32 usage

**Out of scope for M1:**

- Elastic backend
- Cloud rules
- Live SIEM validation
- Any web UI
