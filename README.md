# dryfire

[![CI](https://github.com/aeonstwilight/dryfire/actions/workflows/ci.yml/badge.svg)](https://github.com/aeonstwilight/dryfire/actions/workflows/ci.yml)
![rules](https://img.shields.io/badge/rules-47-blue)
![targets](https://img.shields.io/badge/targets-Splunk%20%7C%20Sentinel%20%7C%20Defender%20%7C%20Elastic-informational)
[![ATT&CK coverage](https://img.shields.io/badge/ATT%26CK-coverage%20map-red)](https://aeonstwilight.github.io/dryfire/)
![license](https://img.shields.io/badge/rules-DRL%201.1-lightgrey) ![license](https://img.shields.io/badge/code-MIT-lightgrey)

Detection-as-code for SOC teams. Every detection is written once as a [Sigma](https://sigmahq.io/) rule, tested against real attack data in CI, and converted to Splunk SPL, Microsoft Sentinel / Defender KQL and Elastic ES|QL. An ATT&CK Navigator layer is generated from the rule tags so coverage is always visible.

## Why

Detections usually live inside a SIEM, untested and undocumented. This repo treats them like code:

- **One source of truth.** Rules are vendor-neutral Sigma YAML; SIEM queries are build output.
- **Tested.** Each rule must fire on a known-malicious sample and stay quiet on benign baseline logs.
- **Documented for the analyst.** Each rule ships with a triage note: what it means when it fires, what to check next, and known false positives.
- **Coverage you can see.** CI publishes an ATT&CK Navigator layer built from the rules.

## Repo layout

```
rules/               Sigma rules, grouped by platform and ATT&CK tactic
tests/cases/         One test case per rule (positive and negative samples, expected hits)
tests/data/          Small checked-in log samples; larger datasets fetched by script
tests/run_tests.py   Runs every rule against its test case
tests/run_sweep.py   Noise sweep over a large corpus, checked against a reviewed baseline
tests/run_validate.py  Runs the converted SPL, KQL and ES|QL on Splunk, Kusto and Elasticsearch containers
pipelines/           Custom pySigma processing pipelines / field mappings
scripts/             convert.py, esql_backend.py, coverage.py, fetch_datasets.py, engines.sh
docs/rules/          Per-rule triage notes
build/               Generated output (gitignored; published as CI artifacts)
```

## How CI works

On every push and pull request:

1. **Lint:** `sigma check` validates every rule.
2. **Convert:** each rule is converted to SPL, KQL and ES|QL; a conversion failure fails the build.
3. **Test:** rules are evaluated against their positive and negative samples with Zircolite.
4. **Coverage:** an ATT&CK Navigator layer is built from rule tags.
5. **Noise sweep:** every rule runs over EVTX-ATTACK-SAMPLES and OTRF APT29; any change from the reviewed per-rule counts in `tests/sweep_baseline.yml` fails the build.
6. **Robustness check:** each process-creation rule's matched positive events are changed the way an attacker would (upper case, quoted program, extra spaces, cmd carets, other switch spellings, binary moved or renamed; see `tests/variants.yml`) and run again. Any change from the reviewed results in `tests/robustness_baseline.yml` fails the build. Every change is caught except renamed binaries, a gap each triage note states. Registry (Sysmon 13) and CloudTrail rules get their own changes, in the same baseline: value data written with environment variables or 8.3 short names, the WOW6432Node and RunOnce keys; the same API call from another region, an assumed role, a denied attempt, an SDK or a VPC endpoint.
7. **Validate (separate job):** the converted queries run on real query engines, a Splunk Enterprise container and Microsoft's Kusto emulator. Each rule's test samples are loaded into both, and every query must find exactly the events Zircolite finds.
8. **Validate Elastic (separate job):** the same check for the ES|QL queries on an Elasticsearch container, with the test events in the field layout of Elastic's Windows, System and AWS integrations.

Converted queries, test and sweep reports and the coverage layer are uploaded as build artifacts.

Once a week a separate **drift check** (`.github/workflows/drift.yml`) runs lint, convert, test, coverage and the sweep against the newest releases of pySigma, the backends, the pipelines and Zircolite instead of the pinned versions. It changes nothing in the repo; a red run means a newer release changes the results, and pins are moved by hand after review.

> **What validation proves:** the SPL and KQL run and match the Sigma logic on the loaded test events. Kusto has no built-in Sentinel or Defender tables, so `SecurityEvent`, `DeviceProcessEvents`, `DeviceRegistryEvents` and `AWSCloudTrail` are created from Microsoft's column lists and the samples are mapped into them (for example Sysmon 1 → a 4688-style `SecurityEvent` row, Sysmon 13 → a `DeviceRegistryEvents` row). It doesn't prove real Sentinel or Defender data looks exactly like these rows. The mapping is documented at the top of `tests/run_validate.py`.
>
> For Elastic, events are loaded with the field names and data streams Elastic's integrations use (ECS names such as `process.executable`, `winlog.event_data.*`, `aws.cloudtrail.*`), documented in `tests/validate_elastic.py`. Real integration data also types some fields differently (wildcard, text sub-fields); the queries compare whole values with `to_lower()` either way. AWS rules that match inside `requestParameters` mostly can't convert: the integration keeps it as `Map.toString()` text, so they're declared unsupported for Elastic in `pipelines/unsupported_targets.yml`.

## Life of a rule: DCSync

One rule end to end, from the Sigma file to the query each SIEM runs.

**1. The rule** (`rules/windows/credential_access/win_dcsync_replication_by_non_machine_account.yml`, trimmed). Security 4662 with one of the two replication rights that return secrets, by an account that isn't a machine account:

```yaml
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
            - '89e95b76-444d-4c62-991a-0facbeda640c'  # DS-Replication-Get-Changes-In-Filtered-Set
    filter_machine_account:
        SubjectUserName|endswith: '$'
    condition: selection and not filter_machine_account
```

Plain Get-Changes (`1131f6aa`) is left out on purpose: it returns no secrets, so a DCSync gives exactly one hit.

**2. The test case** (`tests/cases/win_dcsync_replication_by_non_machine_account.yml`). It must fire on Mimikatz DCSync (EVTX-ATTACK-SAMPLES), Empire and Covenant DCSync (OTRF), and two synthetic edge cases (Get-Changes-In-Filtered-Set, an upper-case GUID). It must stay at zero on a domain controller replicating with `DC1$` and on synthetic benign reads.

```
PASS  positive: CA_DCSync_4662.evtx: 1 hit(s), expected >= 1
PASS  positive: empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip: 1 hit(s), expected >= 1
PASS  positive: covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip: 1 hit(s), expected >= 1
PASS  positive: win_dcsync_replication_by_non_machine_account_synthetic_positive.json: 2 hit(s), expected >= 2
```

**3. The noise sweep.** Across all of EVTX-ATTACK-SAMPLES and OTRF APT29 it fires only on its own sample. The DC machine accounts replicating in the corpus are what the `$` filter is for.

**4. The conversions**, generated by `make convert`. Nobody hand-writes these:

Splunk (Windows add-on field names):

```
source="WinEventLog:Security" EventCode=4662 Properties IN ("*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*", "*89e95b76-444d-4c62-991a-0facbeda640c*") NOT SubjectUserName="*$"
```

Microsoft Sentinel (`SecurityEvent`):

```
SecurityEvent
| where (EventID == 4662 and (Properties contains "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" or Properties contains "89e95b76-444d-4c62-991a-0facbeda640c")) and (not(SubjectUserName endswith "$"))
```

Elastic ES|QL (ECS names, case-insensitive through `to_lower`, the System integration's data stream):

```
from logs-system.security-* metadata _id, _index, _version | where to_lower(winlog.channel)=="security" and to_lower(event.code)=="4662" and (to_lower(winlog.event_data.Properties) like "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" or to_lower(winlog.event_data.Properties) like "*89e95b76-444d-4c62-991a-0facbeda640c*") and not ends_with(to_lower(winlog.event_data.SubjectUserName), "$")
```

Defender XDR is declared unsupported in `pipelines/unsupported_targets.yml`, with the reason: the Kusto backend files 4662 under its registry category and picks `DeviceRegistryEvents`, which would be a wrong query, not a missing one.

**5. The real engines.** `make validate` loads the same positive and negative events into a Splunk container and the Kusto emulator, and `make validate-elastic` loads them into Elasticsearch. Each converted query has to return exactly the hits Zircolite found. A query that runs but finds a different number fails the build.

**6. The analyst's side.** `docs/rules/win_dcsync_replication_by_non_machine_account.md` covers what to check when it fires: the account, whether it's an Entra Connect `MSOL_` account or another approved sync tool, whether the source host matches that tool's server, and what to do if it's real. It also lists the known gap: DCSync from a stolen computer account ends in `$`, so this rule misses it.

## Rule coverage

| Rule | Tactic | Technique | SPL | KQL | ES\|QL | Tested |
|------|--------|-----------|-----|-----|--------|--------|
| [LSASS Process Opened With Memory Read Access](docs/rules/win_lsass_memory_access.md) | Credential Access | T1003.001 | ✅ | — | ✅ | ✅ |
| [Windows Password Spray From One Source](docs/rules/win_password_spray_from_one_source.md) | Credential Access | T1110.003 | ✅ | — | ✅ | ✅ |
| [Windows Brute Force Against One Account From One Source](docs/rules/win_brute_force_one_account_from_one_source.md) | Credential Access | T1110.001 | ✅ | — | ✅ | ✅ |
| [Directory Secrets Replicated by a Non-Machine Account (DCSync)](docs/rules/win_dcsync_replication_by_non_machine_account.md) | Credential Access | T1003.006 | ✅ | Sentinel only | ✅ | ✅ |
| [SAM or SECURITY Hive, or NTDS.dit, Copied for Offline Credential Extraction](docs/rules/win_sam_security_hive_or_ntds_dumped.md) | Credential Access | T1003.002, T1003.003, T1003.004 | ✅ | ✅ | ✅ | ✅ |
| [PowerShell Launched With Encoded or Base64-Decoded Command](docs/rules/win_powershell_encoded_command.md) | Execution, Stealth | T1059.001, T1027.010 | ✅ | ✅ | ✅ | ✅ |
| [Scheduled Task Created With Script Host, LOLBin or User-Writable Path Action](docs/rules/win_scheduled_task_suspicious_action.md) | Persistence, Execution | T1053.005 | ✅ | Sentinel only | ✅ | ✅ |
| [Service Installed With Shell, Named Pipe, User-Folder or Path-Less Image Path](docs/rules/win_service_install_suspicious_image_path.md) | Persistence, Privilege Escalation, Execution | T1543.003, T1569.002 | ✅ | — | ✅ | ✅ |
| [Windows Security Event Log Cleared](docs/rules/win_security_log_cleared.md) | Defense Impairment | T1685.005 | ✅ | Sentinel only | ✅ | ✅ |
| [Windows Event Log Other Than Security Cleared](docs/rules/win_system_log_cleared.md) | Defense Impairment | T1685.005 | ✅ | — | ✅ | ✅ |
| [Certutil Downloading From a URL](docs/rules/win_certutil_download.md) | Command and Control | T1105 | ✅ | ✅ | ✅ | ✅ |
| [Office Application Spawning a Shell or Script Host](docs/rules/win_office_spawning_shell_or_script_host.md) | Execution | T1204.002, T1059.001, T1059.003 | ✅ | ✅ | ✅ | ✅ |
| [WMI Provider Host Spawning a Shell, Proxy Binary or User-Folder Executable](docs/rules/win_wmiprvse_suspicious_child.md) | Execution | T1047 | ✅ | ✅ | ✅ | ✅ |
| [Member Added to Local Administrators Group](docs/rules/win_local_admin_group_member_added.md) | Persistence, Privilege Escalation | T1098.007 | ✅ | Sentinel only | ✅ | ✅ |
| [Rundll32 Running Script, Proxy Export, User-Folder DLL or No Arguments](docs/rules/win_rundll32_suspicious_usage.md) | Stealth | T1218.011 | ✅ | ✅ | ✅ | ✅ |
| [PsExec Service Installed](docs/rules/win_psexec_service_installed.md) | Lateral Movement, Execution | T1021.002, T1569.002 | ✅ | — | ✅ | ✅ |
| [PsExec-Style Named Pipes Created or Connected](docs/rules/win_psexec_named_pipes.md) | Lateral Movement, Execution | T1021.002, T1569.002 | ✅ | — | ✅ | ✅ |
| [Renamed Shell, Script Host or LOLBin Executed](docs/rules/win_renamed_shell_or_lolbin.md) | Stealth | T1036.003 | ✅ | Defender only | ✅ | ✅ |
| [Certutil Encoding or Decoding a Non-Certificate File](docs/rules/win_certutil_encode_decode.md) | Stealth | T1140, T1027 | ✅ | ✅ | ✅ | ✅ |
| [LSASS Opened by a Process From a User or Network Path](docs/rules/win_lsass_access_from_user_path.md) | Credential Access | T1003.001 | ✅ | — | ✅ | ✅ |
| [Member Added to a Privileged Built-in Group Other Than Administrators](docs/rules/win_privileged_builtin_group_member_added.md) | Persistence, Privilege Escalation | T1098.007 | ✅ | Sentinel only | ✅ | ✅ |
| [Member Added to a Domain Admin Group](docs/rules/win_domain_admin_group_member_added.md) | Persistence, Privilege Escalation | T1098.007 | ✅ | Sentinel only | ✅ | ✅ |
| [WMI Event Subscription Bound to a Command Line or Script Consumer](docs/rules/win_wmi_event_subscription_code_consumer.md) | Persistence, Privilege Escalation | T1546.003 | ✅ | — | ✅ | ✅ |
| [Run Key Value Pointing to a Script Host, LOLBin or User-Writable Path](docs/rules/win_run_key_script_or_user_path_value.md) | Persistence, Privilege Escalation | T1547.001 | ✅ | Defender only | ✅ | ✅ |
| [Rundll32 Loading a DLL by Bare Name Not on the Allow-List](docs/rules/win_rundll32_relative_path_dll.md) | Stealth | T1218.011 | ✅ | ✅ | ✅ | ✅ |
| [Shadow Copies, Backup Catalog or Boot Recovery Deleted or Disabled](docs/rules/win_inhibit_system_recovery.md) | Impact | T1490 | ✅ | ✅ | ✅ | ✅ |
| [AWS CloudTrail Logging Stopped or Trail Deleted](docs/rules/aws_cloudtrail_logging_stopped_or_deleted.md) | Defense Impairment | T1685.002 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS CloudTrail Trail Configuration or Event Selectors Changed](docs/rules/aws_cloudtrail_logging_config_changed.md) | Defense Impairment | T1685.002 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS Root Account Console Login](docs/rules/aws_root_console_login.md) | Initial Access, Privilege Escalation | T1078.004 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS IAM User Console Login Without MFA](docs/rules/aws_iam_user_console_login_without_mfa.md) | Initial Access | T1078.004 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS Root Account Access Key Used](docs/rules/aws_root_access_key_used.md) | Persistence, Privilege Escalation | T1078.004 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS IAM Access Key Created for Another User](docs/rules/aws_iam_access_key_created_for_other_user.md) | Persistence | T1098.001 | ✅ | — | — | ✅ |
| [AWS IAM MFA Device Deactivated](docs/rules/aws_iam_mfa_device_deactivated.md) | Persistence, Credential Access | T1556.006 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS IAM Login Profile Created or Updated](docs/rules/aws_iam_login_profile_created_or_updated.md) | Persistence | T1098.001 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS IAM Administrator-Level Policy Granted](docs/rules/aws_iam_admin_policy_granted.md) | Privilege Escalation, Persistence | T1098.003 | ✅ | Sentinel only | — | ✅ |
| [AWS Security Group Ingress Opened to the Internet](docs/rules/aws_security_group_ingress_open_to_internet.md) | Defense Impairment | T1686.001 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS Network ACL Inbound Rule Opened to the Internet](docs/rules/aws_network_acl_ingress_open_to_internet.md) | Defense Impairment | T1686.001 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS S3 Block Public Access Removed or Weakened](docs/rules/aws_s3_public_access_block_disabled.md) | Defense Impairment | T1685 | ✅ | Sentinel only | — | ✅ |
| [AWS S3 Bucket Made Public by Policy or ACL](docs/rules/aws_s3_bucket_made_public.md) | Collection | T1530 | ✅ | Sentinel only | — | ✅ |
| [AWS S3 Bucket Policy Grants Access to a Whole AWS Account](docs/rules/aws_s3_bucket_policy_cross_account_access.md) | Exfiltration | T1537 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS EBS Snapshot, AMI or RDS Snapshot Shared With Another Account or Made Public](docs/rules/aws_ec2_or_rds_snapshot_shared_outside_account.md) | Exfiltration | T1537 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS GuardDuty Detector Deleted, Disabled or Detached](docs/rules/aws_guardduty_disabled.md) | Defense Impairment | T1685 | ✅ | Sentinel only | — | ✅ |
| [AWS GuardDuty Findings Suppressed or Trusted IP List Changed](docs/rules/aws_guardduty_findings_suppressed.md) | Defense Impairment | T1685 | ✅ | Sentinel only | — | ✅ |
| [AWS KMS Key Disabled, Scheduled for Deletion or Key Material Deleted](docs/rules/aws_kms_key_disabled_or_deletion_scheduled.md) | Impact | T1485 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS S3 Bucket Versioning Suspended](docs/rules/aws_s3_bucket_versioning_suspended.md) | Impact | T1490 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS SSM SendCommand Running a Shell or Script Document](docs/rules/aws_ssm_send_command_run_script.md) | Execution | T1651 | ✅ | Sentinel only | ✅ | ✅ |
| [AWS Secrets Manager Many Distinct Secrets Read by One Identity](docs/rules/aws_secretsmanager_many_secrets_read.md) | Credential Access | T1555.006 | ✅ | — | — | ✅ |

## Adding a rule

1. Write the rule as `rules/<platform>/<tactic>/<prefix>_<short_description>.yml` (prefix `win` or `aws`; the tactic folder must be one of the rule's tactic tags).
2. Include a UUID `id`, ATT&CK tags (`attack.<tactic>`, `attack.tXXXX`), `level`, `falsepositives` and `references` (with the technique's attack.mitre.org page). `make lint` checks all of these.
3. Add a test case in `tests/cases/` with positive samples (should fire) and negative samples (should not). New public datasets go in `tests/datasets.yml`, pinned to a commit with their SHA-256.
4. Write a triage note in `docs/rules/` from `docs/rules/_template.md`.
5. Run `make sweep` and add the rule's reviewed per-source counts to `tests/sweep_baseline.yml`. For a process-creation, registry or CloudTrail rule, also run `make robustness` and add its results to `tests/robustness_baseline.yml`.
6. If a target genuinely can't express the rule, declare it in `pipelines/unsupported_targets.yml` with the reason. Otherwise an unmapped field fails the build.
7. Run `make lint convert test coverage` locally, then open a pull request.

## Running locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/fetch_datasets.py   # pull test datasets
make lint convert test coverage
make sweep                         # noise sweep (~110 MB download)
make robustness                    # attacker-style changes to positive events
make engines-up validate engines-down   # needs Docker; ~11 GB of images
make elastic-up validate-elastic elastic-down
```

`make engines-up` and `make elastic-up` start the official Splunk Enterprise, Kusto emulator and Elasticsearch images, and accept their licence terms for you: the [Splunk General Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html), Microsoft's licence terms for the Kusto emulator (`ACCEPT_EULA=Y`), and the [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license). Only run them if you accept those terms. The containers run locally with a random password per run.

## Roadmap

- **M1 (done):** Ten tested Windows rules, SPL and KQL output, coverage layer, CI pipeline
- **M2 (done):** Noise sweep over a larger corpus with a reviewed baseline that CI checks; stricter rule metadata checks; nine more rules
- **M3 (done):** Validate converted queries on real query engines (Splunk container, Kusto emulator)
- **M4 (done):** Twelve AWS CloudTrail rules through the same pipeline (lint, convert, test, coverage, sweep, validate), including the first Sigma correlation rule
- **M5 (done):** Elastic target: ES|QL with ECS field names, validated on an Elasticsearch container
- **M6 (done):** Four more rules: network ACL and cross-account S3 bucket policy (AWS), password spray and brute force (Windows correlation rules)
- **M7 (done):** Eight rules for coverage gaps (Windows impact, credential access and WMI persistence; AWS KMS, MFA and snapshot sharing), a weekly dependency drift check, and a robustness check of every process-creation rule against attacker-style changes to its samples, with a reviewed baseline that CI checks
- **M8 (done):** Four more rules: AWS login profile created/updated, S3 versioning suspended, SSM SendCommand; Windows Run-key persistence (with Defender validation on a new `DeviceRegistryEvents` table)
- **M9 (done):** Robustness checks for registry and CloudTrail rules, reviewed and added to the baseline; the Run-key rule tuned for environment-variable and short-name paths
- **M10 (planned):** Microsoft 365 and Entra ID as a third platform, converted to Microsoft Sentinel

## Data sources

- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (GPL-3.0): Windows event logs mapped to ATT&CK
- [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) (MIT, Copyright (c) 2021 Open Threat Research Forge): recorded attack and benign telemetry
- [Invictus IR Sigma-AWS](https://github.com/invictus-ir/Sigma-AWS) (MIT, Copyright (c) 2023 Invictus Incident Response): the `CloudTrail/` dataset, Stratus Red Team AWS techniques recorded in a test account. Only the data is used, not the repo's Sigma rules.
- [Splunk Attack Data](https://github.com/splunk/attack_data) (Apache 2.0): per-technique AWS CloudTrail datasets

## How this was built

I built dryfire with Claude Code, and I want to be upfront about the split. Claude wrote the code: the pipeline scripts, the backends and the loaders, and the Sigma YAML from logic I specified. What's mine is the detection side. I decided what each rule detects and what it deliberately doesn't, reviewed every noise-sweep hit and labeled it, chose which robustness misses to accept, and set the guardrails in [CLAUDE.md](CLAUDE.md): original rules only, public data only, ATT&CK only, and a real-engine check for every converted query. Every rule's logic decision is recorded there with its date.

## License and attribution

- **Rules** (everything under `rules/`): [Detection Rule License (DRL) 1.1](LICENSE.Detection.Rules.md), the license SigmaHQ uses. Use, change and share them freely; keep the `author` field and a link back to this repo when you do.
- **Code** (scripts, pipelines, tests, CI): [MIT](LICENSE).
- **Datasets**: downloaded at test time by `scripts/fetch_datasets.py`, not redistributed here. Each stays under its own license (see Data sources).
- **Checked-in samples** (`tests/data/samples/`): synthetic, except for 27 trimmed real events in some benign samples, taken from OTRF Security Datasets (MIT). Each names its source in its `SampleSource` field and stays under that licence. See [tests/data/samples/NOTICE.md](tests/data/samples/NOTICE.md).

Rules in this repo are original unless noted. Any rule adapted from [SigmaHQ](https://github.com/SigmaHQ/sigma) is credited in its `references` and `author` fields, per the DRL.
