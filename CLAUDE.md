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
- `make convert`: SPL, KQL and ES|QL into `build/`
- `make test`: run `tests/run_tests.py`; non-zero exit on any failure
- `make coverage`: write `build/coverage/layer.json`
- `make all`: all of the above, in order
- `make sweep`: noise sweep over `tests/sweep_corpus.yml`; report in `build/sweep/`, checked against `tests/sweep_baseline.yml` once it exists
- `make validate` (M3): run the converted SPL and KQL on the Splunk and Kusto containers; report in `build/validate/`
- `make validate-elastic` (M5): run the converted ES|QL on the Elasticsearch container (`make elastic-up`); report in `build/validate/results_elastic.md`

CI (`.github/workflows/ci.yml`) runs `make all` and `make sweep` on push and pull request and uploads `build/` as an artifact. A second job, `validate`, starts both engines (`make engines-up`) and runs `make validate`; a third, `validate-elastic`, starts Elasticsearch (`make elastic-up`) and runs `make validate-elastic`. A separate weekly workflow, `.github/workflows/drift.yml`, runs the same stages against the newest tool releases (report-only, M7).

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

## Milestone 5 (done)

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

**Notes from the build (2026-10-18):**

- `scripts/esql_backend.py` (`DryfireESQLBackend`): `to_lower()` string matches, Lucene regex translation, and `like` patterns written by us: the package's backend leaves literal backslashes single in `LIKE` (`*\users\*`), which Elasticsearch rejects.
- Pipelines: `sysmon` + `ecs_windows` + `pipelines/elastic_windows.yml` (plain ECS fields, data streams, allowed fields), and `pipelines/elastic_cloudtrail.yml`. `convert.py` also fails an Elastic CloudTrail query that still holds a raw CloudTrail field name, which catches correlation fields (pipelines only check detection fields).
- Limit: `ecs_windows` maps any unknown Windows field to `winlog.event_data.<name>`, so on Windows the allowed-fields check can't catch a misspelled field (the same as the Splunk target).
- Result: 24 of 31 rules convert; the 7 AWS rules needing structured request fields (including the Secrets Manager correlation, step 5) are declared for Elastic. `make validate-elastic`: 115 checks, all match Zircolite. Loader: `tests/validate_elastic.py`; own CI job `validate-elastic`.

**Out of scope for M5:** new rules (M6, or slotted in between with the owner's say), other clouds, Elastic Cloud or any real tenant, Kibana detection-rule import, web UI.

## Milestone 6 (done)

More detections on the current pipeline (owner decision, 2026-10-18): the AWS follow-ups (network ACL opened, cross-account S3 bucket policy) and Windows correlation rules (password spray, brute force followed by a successful logon). Each rule follows the usual process; the owner confirms the logic first. Done 2026-10-19: four rules (the brute-force rule without the "followed by success" part, see below); 35 rules in all.

**Rule notes:**

- `aws_network_acl_ingress_open_to_internet` (2026-10-19): inbound only, any port and protocol, failed calls included, medium. `egress` false is matched as `(^|[:=]\s*)false`, which matches the field value, Sentinel's JSON text and Elastic's `Map.toString()` text; the owner allowed this regex for Elastic (an exception to "plain contains only"), proven by validate.
- `aws_s3_bucket_policy_cross_account_access` (2026-10-19): an Allow plus a whole-account principal (root ARN or bare 12-digit ID), not tied to the same statement; a grant to the bucket's own account root also matches (Sigma can't compare the ID in the policy with `recipientAccountId`); single roles/users in other accounts are not covered. Medium, T1537. Patterns accept `:`/`=` and optional quotes so they work on JSON, Zircolite's text and Elastic's `Map.toString()` text (owner decision); `"AWS"` must be a whole key so `AWS:SourceAccount` conditions don't match.
- `win_password_spray_from_one_source` (2026-10-19): correlation over two base rules (4625 SubStatus 0xc000006a/0xc0000064, 4771 Status 0x18; local/loopback sources excluded), 10+ distinct `TargetUserName` per `IpAddress` in 30 minutes, medium, T1110.003. Synthetic positives only (no public spray above the threshold in the corpus). Sentinel and Defender declared (no correlation support). On Elastic `IpAddress` is `source.ip`, an ip field: our backend writes `to_lower(to_string(source.ip))`, the loader stores it as type ip, and Elastic stores `::ffff:a.b.c.d` as `a.b.c.d`, so NTLM and Kerberos failures from one host are counted together there but apart elsewhere (samples avoid that mix). Validate now gives Windows events their `SystemTime` as Splunk's `_time` (test index retention raised to 50 years), and puts the per-sample filter inside each `multisearch` search.
- `win_brute_force_one_account_from_one_source` (2026-10-19): replaces "brute force followed by a successful logon". Sigma correlations that chain an `event_count` into a `temporal` sequence don't convert (Splunk puts `stats` inside `multisearch`; ES|QL nests a query in `eval case`), and neither backend has `temporal_ordered`. So: `event_count` of 10+ wrong-password failures (4625 0xc000006a, 4771 0x18) per `TargetUserName` and `IpAddress` in 30 minutes, medium, T1110.001; the success check is the first triage step (owner decision). Synthetic positives; Sentinel and Defender declared.

## Milestone 7 (planned)

Milestone 7 is done when 6–8 new rules covering current gaps pass the full pipeline, and a robustness check reports, for every rule, which attacker-style changes to its positive samples it still catches.

**Owner decisions (2026-10-19):**

- Two parts: coverage rules first, then robustness testing.
- 6–8 rules, chosen from the step 1 shortlist below. Each one goes through the usual process (owner confirms logic; rule, test case and triage note; must pass sweep and validate).
- Side task: a dependency drift check (below), independent of the rest.

**Part A: coverage rules**

1. Data check: which candidates have positives in the allowed datasets at the pinned commits (done, findings below).
2. The owner picks the shortlist (done, 2026-10-19): the recommended eight, in this order:
   1. Inhibit system recovery (Windows)
   2. DCSync (Windows)
   3. SAM/SECURITY hive and NTDS.dit dumping (Windows)
   4. WMI event subscription (Windows)
   5. KMS key disabled or scheduled for deletion (AWS)
   6. IAM user console login without MFA (AWS)
   7. MFA device deactivated or deleted (AWS)
   8. EBS snapshot or AMI shared publicly or cross-account (AWS)
3. Rules one at a time, same process as before.

**Rule notes:**

- `win_inhibit_system_recovery` (2026-10-19): binary plus action for vssadmin (`delete`+`shadows`, `resize`+`shadowstorage`), wmic (`shadowcopy`+`delete`), PowerShell (`win32_shadowcopy` + `.delete(` / `remove-ciminstance` / `remove-wmiobject`; synthetic positives only, added on Claude's recommendation when the owner asked for its view), wbadmin (`delete` + `catalog`/`backup`) and bcdedit (`recoveryenabled`+` no`, `bootstatuspolicy`+`ignoreallfailures`). High, T1490. No `OriginalFileName` (Sentinel has no such column), so the binary match keeps a `cmd /c` wrapper from counting twice. Sweep: only its 4 own Panache hits.

**Step 1 findings (2026-10-19):** counts are matching events found by a rough scan, not rule hits.

- Windows, with public positives:
  - Inhibit system recovery (`vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit ... recoveryenabled no` / `bootstatuspolicy`): EVTX `PanacheSysmon_vs_AtomicRedTeam01` (Sysmon 1). No other hits in the corpus. T1490, first `impact` rule.
  - DCSync (4662 with the replication GUIDs `1131f6aa-…`, `1131f6ad-…`, `89e95b76-…`): EVTX `CA_DCSync_4662` (Administrator), OTRF `empire_dcsync_…` and `covenant_dcsync_…` (pgustavo). In the sweep only DC machine accounts (`DC1$`, `NEWYORK$`), which a `$` exclusion removes.
  - SAM/SECURITY hive and NTDS.dit dumping (`reg save hklm\sam|security|system`, `ntdsutil ifm`, `esentutl /vss`, copy from a shadow copy): OTRF `cmd_dumping_ntds_dit_file_ntdsutil`, `cmd_dumping_ntds_dit_file_volume_shadow_copy`, `cmd_sam_copy_esentutl`, `empire_shell_reg_dump_sam`, plus Panache.
  - WMI event subscription (Sysmon 19/20/21): EVTX `sysmon_20_21_1_CommandLineEventConsumer`, `wmighost_sysmon_20_21_1`, Panache; OTRF `empire_wmi_local_event_subscriptions_elevated_user`, `covenant_wmi_remote_event_subscription_ActiveScriptEventConsumers`. Sentinel/Defender would be declared (Sysmon other than process creation).
  - Run-key persistence (Sysmon 13): positives in OTRF `empire_persistence_registry_modification_run_keys_*` and Panache, but the sweep has benign writes (`MsMpEng.exe` `…\Run\WindowsDefender`, Teams), so it needs an allow-list or a value-content condition.
- Windows, synthetic positives only:
  - Kerberoasting (4769 RC4 `0x17`): no 0x17 ticket anywhere in the corpus or candidate files.
  - Defender tampering (`Set-MpPreference`/`Add-MpPreference -Exclusion…`, `DisableRealtimeMonitoring`): no command-line hits; the only registry hits are `MsMpEng.exe` itself writing exclusions in APT29 (benign for this purpose).
- AWS (event counts across the downloaded AWS corpus):
  - KMS key disabled or scheduled for deletion: `ScheduleKeyDeletion` 1, `DisableKey` 1 (attack_data `T1486/aws_kms_key`).
  - IAM user console login without MFA: `ConsoleLogin` by `IAMUser`, success, `MFAUsed=No`: 5; with MFA: 1. Uses `additionalEventData.MFAUsed`, which needs a Sentinel/Elastic mapping decision.
  - MFA device deactivated or deleted: `DeactivateMFADevice` 2, `DeleteVirtualMFADevice` 2.
  - EBS snapshot or AMI shared (public or another account): `ModifySnapshotAttribute` 11, `ModifyImageAttribute` 6. Matches inside `requestParameters`, so Sentinel/Elastic need the per-rule design used before.
  - Also available: `SendCommand` 3 (SSM), `PutBucketVersioning` 2, `ModifyInstanceAttribute` 2 (EC2 user data), `CreateLoginProfile` 9 / `UpdateLoginProfile` 2.

**Part B: robustness testing**

1. A variants file (`tests/variants.yml`) lists the changes to try per field, each one valid for that field: case changes, `^` carets and extra quotes in `cmd` command lines, extra spaces, `/` vs `-` flags, PowerShell parameter abbreviations (`-enc`, `-EncodedCommand`, `-e`), renamed or moved binaries. The owner decides which changes apply to which rules.
2. `make robustness`: takes each rule's positive events, writes the changed copies (synthetic, from public samples), runs Zircolite and reports per rule and change whether the rule still fires, in `build/robustness/`. Report-only at first.
3. The owner reviews the report: a miss is either tuned (with sign-off on the logic change) or accepted and written in the triage note. Then the reviewed results become a baseline that CI checks, as for the sweep.

**Side task: dependency drift check (done, 2026-10-19)**

- `.github/workflows/drift.yml` (Mondays 05:17 UTC, plus manual run) runs `scripts/drift.sh`, which installs the newest release of every package in `requirements.txt` and the newest Zircolite (into `tools/zircolite-latest/`, checked against the release's `SHA256SUMS`), then runs lint, convert, test, coverage and sweep with them. Engine images are a later step.
- Report-only: it never changes pins in the repo. A red run means a newer version changes results; pins are moved by hand after review.
- `build/drift/versions.md` lists pinned, tested and newest released versions. It also flags a package that pip held back because of another package's version limit.
- First local run (2026-10-19): Zircolite 4.6.0 (pinned 4.5.0) passes test and sweep unchanged; pySigma 2.0.1 is out but held at 1.5.1 by the backends' version limits; everything else is current.
