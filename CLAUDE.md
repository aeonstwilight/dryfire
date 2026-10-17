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
- **Public tools only.** Build the pipeline only from public tools (pySigma, sigma-cli, Zircolite, GitHub Actions, Make). Don't model the CI, repo structure or tooling on any employer's internal detection-as-code pipeline.
- **ATT&CK is the only framework mapping.** Do not add NIST 800-53, FedRAMP or any other compliance-control mapping: no control tags in rules, no control fields in test cases or triage notes, no control columns in reports or coverage output.
- **No document generation.** Don't add features that generate compliance, audit or customer-facing documents from the rules. The per-rule triage notes are hand-written Markdown, and `build/` holds only build reports (conversion summary, test results, Navigator layer).
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
- ATT&CK tags are validated against a pinned ATT&CK version (v20.0, set in `scripts/lint.py`). Use v20 tactic names: `attack.stealth` and `attack.defense-impairment`, not `attack.defense-evasion`.
- Conversion targets (owner decisions, 2026-10-17):
  - Splunk: Sysmon-based (`sysmon` + `splunk_windows` pipelines) for every rule.
  - Sentinel: Security-log rules (e.g. 4698, 1102, 4732) get a custom table mapping to `SecurityEvent` in `pipelines/`, checked field by field per rule. System 7045 and Sysmon rules other than process creation stay "unsupported" for M1.
  - Defender XDR: anything outside the backend's built-in tables stays "unsupported" for M1. Revisit in M3.
  - A rule field that doesn't exist in the target table fails the build. Don't relax this.
  - The only exception: a rule/target pair listed in `pipelines/unsupported_targets.yml` with a reason, approved by the owner (owner decision, 2026-10-17). `convert.py` reports it as "unsupported (declared)", and fails if a listed pair converts after all or names a rule that doesn't exist.
- `build/` is generated and gitignored. Never hand-edit it.
- Keep large datasets out of git; `scripts/fetch_datasets.py` downloads them into `tests/data/external/` (gitignored). Only small, trimmed samples are checked in.

## Commands

The Makefile should expose these targets:

- `make lint`: `sigma check` on all rules
- `make convert`: SPL and KQL into `build/`
- `make test`: run `tests/run_tests.py`; non-zero exit on any failure
- `make coverage`: write `build/coverage/layer.json`
- `make all`: all of the above, in order
- `make sweep`: noise sweep over `tests/sweep_corpus.yml`; report in `build/sweep/`, checked against `tests/sweep_baseline.yml` once it exists

CI (`.github/workflows/ci.yml`) runs `make all` and `make sweep` on push and pull request and uploads `build/` as an artifact.

## Milestone 1 (done, merged in PR #1)

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

## Milestone 2 (current)

Milestone 2 is done when CI enforces rule metadata, a noise sweep over a large corpus has a reviewed per-rule baseline that CI checks, and the follow-up rules below are added and passing.

**Build order:**

1. **Metadata checks.** `scripts/check_metadata.py`, run by `make lint`, fails on:
   - a missing required field (see Conventions), an `id` that isn't a UUID, a `date` not in `YYYY-MM-DD` form, or a `status`/`level` outside the Sigma values
   - no ATT&CK tactic tag, or no technique tag
   - a path not matching `rules/<platform>/<tactic>/<prefix>_<short_description>.yml`, where the `<tactic>` folder must be one of the rule's tactic tags (hyphens as underscores)
   - empty `falsepositives` or `references`, or no `attack.mitre.org` reference for any tagged technique
   - a triage note missing one of the five template sections, still containing template placeholders (`<...>`), or whose Rule ID doesn't match the rule
2. **Noise sweep.** `make sweep` runs every rule against a large mostly-normal corpus and writes per-rule hit counts and sample hits to `build/sweep/`.
   - Corpus (same sources as the tests): OTRF APT29 day 1 and day 2, and the whole EVTX-ATTACK-SAMPLES set at the pinned commit.
   - Report-only in CI first. The owner reviews every hit and labels it as an attack or a false positive; false positives are tuned (with the owner's sign-off on any logic change).
   - Then the reviewed counts go into `tests/sweep_baseline.yml` and CI fails when a rule's count changes from its baseline.
3. **Follow-up rules**, one at a time, same process as M1 (owner confirms logic; rule, test case and triage note; must also pass the sweep):
   - System log cleared (System 104, provider `Microsoft-Windows-Eventlog`)
   - PsExec service installed (`PSEXESVC`, including renamed PsExec)
   - Renamed PowerShell, and renamed system utilities (certutil and similar)
   - certutil encode/decode
   - LSASS access from unbacked memory (CallTrace `UNKNOWN`), and PPLdump-style access. **Decision (2026-10-17):** the `UNKNOWN`-frame rule was rejected (2 uncertain hits vs 8 .NET-agent false positives in the sweep corpus); PPLdump-style access is covered instead by `win_lsass_access_from_user_path` (any mask outside the memory-read rule's list, from a user/temp/network path).
   - Members added to other privileged built-in groups (Remote Desktop Users, Backup Operators, Remote Management Users)
   - Members added to domain admin groups (4728/4756), including DnsAdmins (domain-local, matched by name; deferred here from the built-in groups rule, owner decision 2026-10-17)
   - Rundll32 with a relative-path DLL (needs an allow-list approach)

**Out of scope for M2:** the same as M1 (Elastic, cloud rules, live SIEM validation, web UI).
