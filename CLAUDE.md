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
- **No secrets or real environment data** in the repo. Test data comes only from public datasets (EVTX-ATTACK-SAMPLES, OTRF Security Datasets, and for AWS: the `CloudTrail/` data folder of Invictus IR Sigma-AWS and the AWS datasets in Splunk attack_data, owner decision 2026-10-18) or is synthetic. From Invictus IR Sigma-AWS use only the data, never its Sigma rules.
- **Public tools only.** Build the pipeline only from public tools (pySigma, sigma-cli, Zircolite, GitHub Actions, Make). Don't model the CI, repo structure or tooling on any employer's internal detection-as-code pipeline.
- **ATT&CK is the only framework mapping.** Do not add NIST 800-53, FedRAMP or any other compliance-control mapping: no control tags in rules, no control fields in test cases or triage notes, no control columns in reports or coverage output.
- **No document generation.** Don't add features that generate compliance, audit or customer-facing documents from the rules. The per-rule triage notes are hand-written Markdown, and `build/` holds only build reports (conversion summary, test results, Navigator layer).
- **Check current versions.** Verify package names, CLI flags and backend/pipeline names (pySigma, sigma-cli, pySigma-backend-splunk, pySigma-backend-kusto, pySigma-backend-elasticsearch, Zircolite) against their current docs before using them. Don't rely on memory.

## Conventions

- Rule path: `rules/<platform>/<tactic>/<prefix>_<short_description>.yml` (prefix `win` for windows, `aws` for aws)
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
  - Defender XDR: anything outside the backend's built-in tables stays "unsupported". Revisited for M3 and kept as is (owner decision, 2026-10-18).
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
- `make validate` (M3): run the converted SPL and KQL on the Splunk and Kusto containers; report in `build/validate/`

CI (`.github/workflows/ci.yml`) runs `make all` and `make sweep` on push and pull request and uploads `build/` as an artifact. A second job, `validate`, starts both engines (`make engines-up`) and runs `make validate`.

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

## Milestone 2 (done)

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

## Milestone 3 (done)

Milestone 3 is done when every converted query runs on a real query engine in CI and returns the same hits as the Zircolite tests.

**Owner decisions (2026-10-18):**

- Engines: the official Splunk Enterprise container (`splunk/splunk`) and Microsoft's Kusto emulator container (`kustainer-linux`). No Azure account, cloud cluster or CI secrets.
- The owner accepts the Splunk licence and General Terms and the Kusto emulator licence terms; the CI settings record that acceptance.
- Runs as a separate CI job on every push and pull request, and fails the build like the other steps.
- Defender targets that don't convert stay "unsupported"; M3 validates only what already converts.

**Build order:**

1. Check current image names, tags, licence settings and APIs for both containers against their docs, and pin image versions.
2. Loader: put each rule's positive and negative test events into the engines. Splunk gets the source and field names the `splunk_windows` pipeline expects; the Kusto emulator gets `SecurityEvent` and `DeviceProcessEvents` tables built from Microsoft's published column lists. Field-to-column mapping is plain and documented, one table per target.
3. `make validate`: run each rule's converted query on its own test events and compare the hit count with Zircolite's. Fail if a query errors or a count differs.
4. CI job, plus a README note: this proves the queries run and match the Sigma logic on our loaded events, not that real Sentinel or Defender data looks exactly like them.

**Notes from the build:**

- Images pinned by digest in `scripts/engines.sh`: Splunk 10.6.0, and the Kusto emulator weekly production build of 2026-09-25.
- Splunk loads events through the HTTP Event Collector; `tests/validate/splunk_app/` adds the `dryfire` index and `TRUNCATE = 0` for `_json`, so long events aren't cut.
- The Kusto emulator accepts `EventID in~ ("4728", "4756")` on the integer column, so the split selections in `win_domain_admin_group_member_added` weren't needed. Kept as is (harmless).

**Out of scope for M3:** Elastic, cloud rules (M4), real Sentinel/Defender/Splunk tenants, web UI.

## Milestone 4 (done)

Milestone 4 is done when the AWS CloudTrail starter rules below are added and passing through the same pipeline as the Windows rules: lint, convert, test, coverage, noise sweep and validate.

**Owner decisions (2026-10-18):**

- Test data: Invictus IR Sigma-AWS (`CloudTrail/` folder only, MIT, pinned commit) and Splunk attack_data AWS datasets (Apache 2.0, pinned commit, files fetched from Git LFS and checked against their published SHA-256), plus OTRF's two AWS datasets. flaws.cloud logs left out (licence not confirmed).
- Conversion targets: Splunk (CloudTrail sourcetype from the AWS add-on) and Sentinel (`AWSCloudTrail` table). Defender has no CloudTrail table, so it's declared unsupported.
- Validation: the M3 `validate` job also loads CloudTrail events into Splunk and an `AWSCloudTrail` table in the Kusto emulator.

**Build order:**

1. Check current docs for: how Zircolite reads CloudTrail files (`{"Records": [...]}`) and flattens nested fields (`userIdentity.type`); the Splunk sourcetype and field names; the `AWSCloudTrail` columns and any pySigma pipeline for them.
2. Pipeline: fetch and pin the datasets, CloudTrail support in conversion (custom pipelines in `pipelines/` where needed), tests, sweep corpus and validation loader.
3. Starter rules, one at a time, same process as before (owner confirms logic; rule, test case and triage note; must pass sweep and validate):
   1. CloudTrail logging stopped, deleted or its event selectors changed
   2. Root account console login
   3. IAM access key created for another user
   4. Admin-level policy attached to a user or role
   5. Security group opened to 0.0.0.0/0 or ::/0
   6. S3 bucket made public (bucket policy or ACL)
   7. GuardDuty detector deleted or disabled
   8. Unusual volume of Secrets Manager `GetSecretValue` calls

**Step 1 findings (2026-10-18):**

- Zircolite 4.5.0 doesn't read CloudTrail's `{"Records": [...]}` files; they must be unwrapped to one event per line (JSON Lines, `-j`).
- Zircolite flattens nested fields to their last key (`userIdentity.type` → `type`) and strips dots from keys. A Zircolite config with `path: path` mappings keeps dotted names; it can be generated from the field paths found in the data.
- Arrays (e.g. `requestParameters.ipPermissions.items`) stay one text column holding the whole list, so array contents can only be matched with `contains`. `AuthorizeSecurityGroupIngress` has two shapes: rules under `ipPermissions.items[].ipRanges` and an older flat `cidrIp`.
- Splunk: no pySigma AWS pipeline; CloudTrail sourcetype is `aws:cloudtrail` (Splunk Add-on for AWS docs). Fields are the dotted JSON paths; array leaves use `{}`.
- Sentinel: pySigma-backend-kusto knows the `AWSCloudTrail` table (53 columns) but has no mapping for the `aws`/`cloudtrail` log source; nested `requestParameters.*` lives in the `RequestParameters` text column.

**Step 2 (pipeline) done, 2026-10-18:**

- `scripts/fetch_datasets.py`: a manifest entry with `jsonl:` also gets a one-event-per-line copy (handles `{"Records": [...]}`, JSON Lines and zips). AWS test cases point at the `.jsonl` files (or a folder of them) and use `pipelines: []`.
- `tests/zircolite_cloudtrail.py`: for CloudTrail samples, writes a Zircolite config (default config plus a `path: path` mapping for every nested field in the sample); used by the test, sweep and validate scripts.
- `pipelines/splunk_cloudtrail.yml` (adds `sourcetype="aws:cloudtrail"`) and `pipelines/sentinel_cloudtrail.yml` (`AWSCloudTrail` table, field-to-column mapping; `requestParameters.*` etc. deliberately unmapped, so a rule using them fails Sentinel conversion until a per-field decision).
- Sweep: sources have a `platform`; rules only run on sources of their own platform. AWS corpus: Invictus IR (55 files), Splunk attack_data (40 raw CloudTrail files) and OTRF EC2 proxy exfiltration, 38,793 events. OTRF's honey-bucket dataset is a CSV export, not CloudTrail, so it's left out.
- Validate: CloudTrail records go to Splunk as `aws:cloudtrail` (nested JSON) and to an `AWSCloudTrail` table in Kusto built from the Sentinel pipeline's mapping. The Splunk test app also lowers `minFreeSpace` (Splunk stops indexing below 5 GB free), and `engines.sh` waits for the Splunk image's health check.
- Found with probe rules: list contents differ by engine. Zircolite keeps a list as one text column (`requestParameters.ipPermissions.items`), Splunk extracts list items as `...items{}.ipRanges.items{}.cidrIp`, Sentinel has them in `RequestParameters`. Rules matching inside lists (security group, S3 public) need a per-rule design.

**Rule notes:**

- Sentinel and `requestParameters.*` (owner decision for rule 4, 2026-10-18): map a nested request field to `RequestParameters` only when the rule matches it with a pattern written to give the same result on the field and on the JSON text (end anchors as `("|$)`, optional `\\` before quotes, literal `\n` allowed), and `make validate` proves it. Otherwise declare Sentinel unsupported, as for `aws_iam_access_key_created_for_other_user` (field-to-field comparison).

- Correlation rules (rule 8, 2026-10-18): one file, base rule(s) first and the correlation rule last (it holds the detection's id, title, level and tags); `scripts/rule_file.py` reads it for the metadata, coverage and sweep scripts. A correlation's hit count is the number of distinct groups over the threshold (Zircolite reports one alert per qualifying moment). Splunk converts to fixed `bin _time` buckets, Zircolite slides; samples keep each burst inside one bucket. pySigma-backend-kusto 1.0.1 doesn't convert correlation rules, so Sentinel is declared unsupported (owner decision, 2026-10-18).

**Out of scope for M4:** Elastic, other clouds (Azure, GCP), real AWS accounts, web UI.

## Milestone 5 (current)

Milestone 5 is done when every rule converts to Elastic (or is declared unsupported with the owner's approval) and the Elastic queries return the same hits as Zircolite on a real Elasticsearch container in CI.

**Owner decisions (2026-10-18):**

- Query language: ES|QL, if pySigma-backend-elasticsearch supports what the rules use (regex, correlations); confirm in step 1 and come back to the owner if not.
- Field names: convert to ECS, the names Elastic's own integrations produce (Windows/Sysmon and AWS CloudTrail), not the raw field names.
- The owner accepts the Elasticsearch container's licence for CI (exact terms named in step 1 and recorded in the CI settings, as for Splunk and Kusto).
- If the runner can't hold Splunk, Kusto and Elasticsearch together, Elastic validation runs as its own CI job.
- Same guardrails as the other targets: a rule field with no mapping fails the build; the only exception is `pipelines/unsupported_targets.yml` with the owner's approval.

**Build order:**

1. Check current docs and versions: pySigma-backend-elasticsearch (ES|QL support, regex, correlations), the ECS field-name pipelines for Windows and for CloudTrail, the Elasticsearch container image, its licence and settings; pin by digest.
2. Conversion: `make convert` writes ES|QL to `build/elastic/`; ECS field mappings in `pipelines/` where the backend's own pipelines don't cover a field.
3. Loader: put each rule's test events into Elasticsearch in the ECS layout the pipeline expects, one index per log source, mapping plain and documented (as for the M3 tables).
4. `make validate`: run each ES|QL query on its own test events and compare the hit count with Zircolite's. CI runs it alongside (or next to) the M3 engines.
5. Correlation rule: convert `aws_secretsmanager_many_secrets_read` if the backend supports it; otherwise ask the owner about declaring it.
6. README: an Elastic column in the rule table, and the validation note extended to Elastic.

**Step 1 findings (2026-10-18):**

- pySigma-backend-elasticsearch 2.1.1 (needs pySigma >=1.4,<2; we have 1.5.1): `ESQLBackend`, with correlation support (`count_distinct` per `date_trunc` bucket, fixed buckets like Splunk). Every rule converts as is, but the output isn't right yet (below).
- Pipelines: `ecs_windows` (Winlogbeat 7+ ECS names; Sysmon fields to `process.*`, `file.*`, others to `winlog.event_data.*`). No CloudTrail pipeline: ours to write from Elastic's AWS integration (aws package 8.11.0 ingest pipeline: `eventName` → `event.action`, `eventSource` → `event.provider`, `userIdentity.type` → `aws.cloudtrail.user_identity.type`, `userIdentity.userName` → `user.name`, ...).
- Engine: official Docker Hub image `elasticsearch:9.5.5` (2026-10-13), digest `sha256:33cae13fc18ef105e960cdd32327d402fbd7c6d4376c0b879ad703ee289d45d8`, runs on the free basic licence (Elastic License 2.0 binary). `docker.elastic.co` is blocked from the dev sandbox. Needs `cluster.routing.allocation.disk.threshold_enabled=false` on a nearly full disk.
- Probed on 9.5.5:
  - `==`, `like`, `starts_with`, `ends_with` are case-sensitive; the backend doesn't lower-case anything. `ecs_windows` maps `Image` etc. to `.caseless` sub-fields, which ignore case only when the condition is pushed down to Lucene (inside an `or` with a non-pushable condition the same match returned 0). `to_lower(field)` works every time.
  - `rlike` is Lucene regex on the whole value: no `^`/`$`, no `(?i)`; `\s` works. The backend passes Sigma regexes through unchanged, so unanchored Sigma regexes don't match.
  - The AWS integration stores `requestParameters` as Java `Map.toString()` text in `aws.cloudtrail.request_parameters` (`{bucketName=x, enable=false}`), not JSON; its structured copy is a `flattened` field, which ES|QL can't query ("Unknown column").

**Owner decisions after step 1 (2026-10-18):**

- Case: our ES|QL backend (a small subclass of the package's) writes every string match as `to_lower(field)` against a lower-cased value, except `|cased` matches; no `.caseless` sub-fields.
- Regex: a small translator wraps Sigma's search-style regex for Lucene's whole-value `rlike` (`.*(…).*`, the anchor forms our rules use, `(?i)` via `to_lower`); a rule it can't translate exactly is declared unsupported for Elastic with the owner's OK; `make validate` proves the rest.
- CloudTrail `requestParameters`: map a request field to `aws.cloudtrail.request_parameters` (the integration's `Map.toString()` text) only where the rule's match gives the same result on that text (plain `contains`), proven by validate; otherwise declare Elastic unsupported for the rule.
- Indexes: queries read the Elastic integrations' data streams (`logs-windows.sysmon_operational-*`, `logs-system.security-*`, `logs-system.system-*`, `logs-aws.cloudtrail-*`), and the loader writes to matching data streams.

**Out of scope for M5:** new rules (M6, or slotted in between with the owner's say), other clouds, Elastic Cloud or any real tenant, Kibana detection-rule import, web UI.

## Milestone 6 (planned)

More detections on the current pipeline (owner decision, 2026-10-18): the AWS follow-ups (network ACL opened, cross-account S3 bucket policy) and Windows correlation rules (password spray, brute force followed by a successful logon). Each rule follows the usual process; the owner confirms the logic first.
