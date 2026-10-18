# dryfire

Detection-as-code for SOC teams. Every detection is written once as a [Sigma](https://sigmahq.io/) rule, tested against real attack data in CI, and converted to Splunk SPL and Microsoft Sentinel / Defender KQL. An ATT&CK Navigator layer is generated from the rule tags so coverage is always visible.

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
tests/run_validate.py  Runs the converted SPL and KQL on Splunk and Kusto containers
pipelines/           Custom pySigma processing pipelines / field mappings
scripts/             convert.py, coverage.py, fetch_datasets.py, engines.sh
docs/rules/          Per-rule triage notes
build/               Generated output (gitignored; published as CI artifacts)
```

## How CI works

On every push and pull request:

1. **Lint:** `sigma check` validates every rule.
2. **Convert:** each rule is converted to SPL and KQL; a conversion failure fails the build.
3. **Test:** rules are evaluated against their positive and negative samples with Zircolite.
4. **Coverage:** an ATT&CK Navigator layer is built from rule tags.
5. **Noise sweep:** every rule runs over EVTX-ATTACK-SAMPLES and OTRF APT29; any change from the reviewed per-rule counts in `tests/sweep_baseline.yml` fails the build.
6. **Validate (separate job):** the converted queries run on real query engines, a Splunk Enterprise container and Microsoft's Kusto emulator. Each rule's test samples are loaded into both, and every query must find exactly the events Zircolite finds.

Converted queries, test and sweep reports and the coverage layer are uploaded as build artifacts.

> **What validation proves:** the SPL and KQL run and match the Sigma logic on the loaded test events. Kusto has no built-in Sentinel or Defender tables, so `SecurityEvent` and `DeviceProcessEvents` are created from Microsoft's column lists and the samples are mapped into them (for example Sysmon 1 → a 4688-style `SecurityEvent` row). It doesn't prove real Sentinel or Defender data looks exactly like these rows. The mapping is documented at the top of `tests/run_validate.py`.

## Rule coverage

| Rule | Tactic | Technique | SPL | KQL | Tested |
|------|--------|-----------|-----|-----|--------|
| [LSASS Process Opened With Memory Read Access](docs/rules/win_lsass_memory_access.md) | Credential Access | T1003.001 | ✅ | — | ✅ |
| [PowerShell Launched With Encoded or Base64-Decoded Command](docs/rules/win_powershell_encoded_command.md) | Execution, Stealth | T1059.001, T1027.010 | ✅ | ✅ | ✅ |
| [Scheduled Task Created With Script Host, LOLBin or User-Writable Path Action](docs/rules/win_scheduled_task_suspicious_action.md) | Persistence, Execution | T1053.005 | ✅ | Sentinel only | ✅ |
| [Service Installed With Shell, Named Pipe, User-Folder or Path-Less Image Path](docs/rules/win_service_install_suspicious_image_path.md) | Persistence, Privilege Escalation, Execution | T1543.003, T1569.002 | ✅ | — | ✅ |
| [Windows Security Event Log Cleared](docs/rules/win_security_log_cleared.md) | Defense Impairment | T1685.005 | ✅ | Sentinel only | ✅ |
| [Windows Event Log Other Than Security Cleared](docs/rules/win_system_log_cleared.md) | Defense Impairment | T1685.005 | ✅ | — | ✅ |
| [Certutil Downloading From a URL](docs/rules/win_certutil_download.md) | Command and Control | T1105 | ✅ | ✅ | ✅ |
| [Office Application Spawning a Shell or Script Host](docs/rules/win_office_spawning_shell_or_script_host.md) | Execution | T1204.002, T1059.001, T1059.003 | ✅ | ✅ | ✅ |
| [WMI Provider Host Spawning a Shell, Proxy Binary or User-Folder Executable](docs/rules/win_wmiprvse_suspicious_child.md) | Execution | T1047 | ✅ | ✅ | ✅ |
| [Member Added to Local Administrators Group](docs/rules/win_local_admin_group_member_added.md) | Persistence, Privilege Escalation | T1098.007 | ✅ | Sentinel only | ✅ |
| [Rundll32 Running Script, Proxy Export, User-Folder DLL or No Arguments](docs/rules/win_rundll32_suspicious_usage.md) | Stealth | T1218.011 | ✅ | ✅ | ✅ |
| [PsExec Service Installed](docs/rules/win_psexec_service_installed.md) | Lateral Movement, Execution | T1021.002, T1569.002 | ✅ | — | ✅ |
| [PsExec-Style Named Pipes Created or Connected](docs/rules/win_psexec_named_pipes.md) | Lateral Movement, Execution | T1021.002, T1569.002 | ✅ | — | ✅ |
| [Renamed Shell, Script Host or LOLBin Executed](docs/rules/win_renamed_shell_or_lolbin.md) | Stealth | T1036.003 | ✅ | Defender only | ✅ |
| [Certutil Encoding or Decoding a Non-Certificate File](docs/rules/win_certutil_encode_decode.md) | Stealth | T1140, T1027 | ✅ | ✅ | ✅ |
| [LSASS Opened by a Process From a User or Network Path](docs/rules/win_lsass_access_from_user_path.md) | Credential Access | T1003.001 | ✅ | — | ✅ |
| [Member Added to a Privileged Built-in Group Other Than Administrators](docs/rules/win_privileged_builtin_group_member_added.md) | Persistence, Privilege Escalation | T1098.007 | ✅ | Sentinel only | ✅ |
| [Member Added to a Domain Admin Group](docs/rules/win_domain_admin_group_member_added.md) | Persistence, Privilege Escalation | T1098.007 | ✅ | Sentinel only | ✅ |
| [Rundll32 Loading a DLL by Bare Name Not on the Allow-List](docs/rules/win_rundll32_relative_path_dll.md) | Stealth | T1218.011 | ✅ | ✅ | ✅ |
| [AWS CloudTrail Logging Stopped or Trail Deleted](docs/rules/aws_cloudtrail_logging_stopped_or_deleted.md) | Defense Impairment | T1685.002 | ✅ | Sentinel only | ✅ |
| [AWS CloudTrail Trail Configuration or Event Selectors Changed](docs/rules/aws_cloudtrail_logging_config_changed.md) | Defense Impairment | T1685.002 | ✅ | Sentinel only | ✅ |
| [AWS Root Account Console Login](docs/rules/aws_root_console_login.md) | Initial Access, Privilege Escalation | T1078.004 | ✅ | Sentinel only | ✅ |
| [AWS Root Account Access Key Used](docs/rules/aws_root_access_key_used.md) | Persistence, Privilege Escalation | T1078.004 | ✅ | Sentinel only | ✅ |
| [AWS IAM Access Key Created for Another User](docs/rules/aws_iam_access_key_created_for_other_user.md) | Persistence | T1098.001 | ✅ | — | ✅ |
| [AWS IAM Administrator-Level Policy Granted](docs/rules/aws_iam_admin_policy_granted.md) | Privilege Escalation, Persistence | T1098.003 | ✅ | Sentinel only | ✅ |
| [AWS Security Group Ingress Opened to the Internet](docs/rules/aws_security_group_ingress_open_to_internet.md) | Defense Impairment | T1686.001 | ✅ | Sentinel only | ✅ |
| [AWS S3 Block Public Access Removed or Weakened](docs/rules/aws_s3_public_access_block_disabled.md) | Defense Impairment | T1685 | ✅ | Sentinel only | ✅ |
| [AWS S3 Bucket Made Public by Policy or ACL](docs/rules/aws_s3_bucket_made_public.md) | Collection | T1530 | ✅ | Sentinel only | ✅ |
| [AWS GuardDuty Detector Deleted, Disabled or Detached](docs/rules/aws_guardduty_disabled.md) | Defense Impairment | T1685 | ✅ | Sentinel only | ✅ |
| [AWS GuardDuty Findings Suppressed or Trusted IP List Changed](docs/rules/aws_guardduty_findings_suppressed.md) | Defense Impairment | T1685 | ✅ | Sentinel only | ✅ |
| [AWS Secrets Manager Many Distinct Secrets Read by One Identity](docs/rules/aws_secretsmanager_many_secrets_read.md) | Credential Access | T1555.006 | ✅ | — | ✅ |

## Adding a rule

1. Write the rule in `rules/<platform>/<tactic>/` using the naming convention `<platform>_<short_description>.yml`.
2. Include ATT&CK tags (`attack.<tactic>`, `attack.tXXXX`), `level`, `falsepositives`, and `references`.
3. Add a test case in `tests/cases/` pointing to a positive sample (should fire) and a negative sample (should not).
4. Write a triage note in `docs/rules/` using the template.
5. Run `make test` locally, then open a pull request.

## Running locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/fetch_datasets.py   # pull test datasets
make lint convert test coverage
make sweep                         # noise sweep (~110 MB download)
make engines-up validate engines-down   # needs Docker; ~11 GB of images
```

## Roadmap

- **M1 (done):** Ten tested Windows rules, SPL and KQL output, coverage layer, CI pipeline
- **M2 (done):** Noise sweep over a larger corpus with a reviewed baseline that CI checks; stricter rule metadata checks; nine more rules
- **M3 (done):** Validate converted queries on real query engines (Splunk container, Kusto emulator)
- **M4 (in progress):** AWS CloudTrail detections

## Data sources

- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES): Windows event logs mapped to ATT&CK
- [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets): recorded attack and benign telemetry
- [Invictus IR Sigma-AWS](https://github.com/invictus-ir/Sigma-AWS) (MIT, Copyright (c) 2023 Invictus Incident Response): the `CloudTrail/` dataset, Stratus Red Team AWS techniques recorded in a test account. Only the data is used, not the repo's Sigma rules.
- [Splunk Attack Data](https://github.com/splunk/attack_data) (Apache 2.0): per-technique AWS CloudTrail datasets

## How this was built

The detection logic, rule design, test strategy and guardrails are mine. Code was written with Claude Code as a coding partner.

## License and attribution

Rules in this repo are original unless noted. Any rule adapted from [SigmaHQ](https://github.com/SigmaHQ/sigma) is credited in its `references` and `author` fields, per the [Detection Rule License](https://github.com/SigmaHQ/Detection-Rule-License).
