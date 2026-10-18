# Noise-sweep review

First full sweep of all ten M1 rules, reviewed and signed off by the owner on 2026-10-17. The counts are recorded in [`sweep_baseline.yml`](sweep_baseline.yml); `make sweep` fails if any of them change.

**Corpus:** every `.evtx` in EVTX-ATTACK-SAMPLES at commit `4ceed2f` (278 files), and OTRF APT29 evaluation day 1 and day 2. See [`sweep_corpus.yml`](sweep_corpus.yml).

**Labels:**

- **Own sample:** a hit in one of the rule's own positive test files.
- **Attack:** a real attack step in another dataset.
- **Correct, benign:** the rule saw exactly what it looks for, but the activity was benign (for example, a lab reset).
- **False positive:** the rule fired on something it shouldn't match.

## Result

No false positives. Every hit outside a rule's own test samples is either an attack or a correct detection of benign activity. No rule was tuned.

| Rule | EVTX (other + own) | APT29 day 1 | APT29 day 2 | Labels |
|---|---|---|---|---|
| win_certutil_download | 0 + 1 | 0 | 0 | own sample only |
| win_lsass_memory_access | 14 + 9 | 3 | 2 | attack; 1 correct, benign (see below) |
| win_security_log_cleared | 22 + 2 | 0 | 0 | 22 correct, benign (lab resets) |
| win_office_spawning_shell_or_script_host | 0 + 1 | 0 | 0 | own sample only |
| win_powershell_encoded_command | 0 + 3 | 1 | 5 | attack |
| win_wmiprvse_suspicious_child | 7 + 5 | 0 | 4 | attack |
| win_local_admin_group_member_added | 0 + 2 | 0 | 0 | own sample only |
| win_scheduled_task_suspicious_action | 1 + 2 | 0 | 0 | attack |
| win_service_install_suspicious_image_path | 0 + 4 | 0 | 0 | own sample only |
| win_rundll32_suspicious_usage | 15 + 9 | 1 | 1 | attack (one borderline, see below) |

## Notes per rule

**win_lsass_memory_access.**
- **EVTX, attack:** PPLdump (`0x1fffff`), procdump/procdump64, Task Manager "Create dump file", Invoke-Mimikatz and babyshark PowerShell (`0x1010`, `0x143a`), Meterpreter hashdump (`0x1f1fff`), Meterpreter process listing (`0x1410`) and MalSeclogon (`0x1410`).
- **APT29, attack:** day 1 has PowerShell and `wsmprovhost.exe` (`0x1f3fff`, `0x1fffff`) during the credential-dumping step; day 2 has the renamed mimikatz `m.exe`.
- **Correct, benign:** `c:\python27\python.exe` opening LSASS with `0x1410` in `sysmon_20_21_1_CommandLineEventConsumer.evtx`. This looks like the sample author's own Python tooling rather than the attack. It's real `PROCESS_VM_READ` access, so the detection is correct. No tuning.

**win_security_log_cleared.** 22 EVTX files contain a 1102 from the sample author clearing the log before recording. These are correct detections of a benign admin action, which the triage note already covers. Deliberately not tuned.

**win_powershell_encoded_command.** APT29 launchers: day 1 `-nop -w hidden -e …`; day 2 `-exec bypass -Noninteractive -windowstyle hidden -e …`, started via `control.exe` and over WMI.

**win_wmiprvse_suspicious_child.** smbmap remote execution (`cmd.exe /Q /c … 1> \\127.0.0.1\C$\…`), PoisonHandler (`rundll32 url.dll`, `cmd /c start ms-browser://`), `comsvcs MiniDump` started over WMI, and APT29 day 2 encoded PowerShell over WMI (as the user and as SYSTEM).

**win_scheduled_task_suspicious_action.** The same atexec-style `\CYAlyNSS` task as the rule's own test sample, recorded in a second file (`LM_ScheduledTask_ATSVC_target_host.evtx`).

**win_rundll32_suspicious_usage.**
- **EVTX, attack:** LOLBin demos (`url.dll` with `file://` or a bare executable, `ieframe`/`shdocvw OpenURL`, `zipfldr`, `pcwutl`), the javascript/mshtml EDR-testing samples, a phishing CPL from `Downloads`, `comsvcs MiniDump`, and a bare rundll32 from Word side-loading.
- **APT29, attack:** day 1 has APT29's `javamtsup.exe` starting a bare `rundll32.exe` as SYSTEM; day 2 has `rundll32 …\AppData\Roaming\Microsoft\kxwn.lock,VoidFunc`.
- **Borderline, labelled attack:** `zipfldr.dll,RouteTheCall shell:::{769f9427-…}` under `explorer.exe`, from a LOLBAS demo sample. A user opening a shell folder could look the same, so this is the first candidate for tuning if it shows up in production.

## Additions

| Date | Rule | Hits outside own samples | Notes |
|---|---|---|---|
| 2026-10-17 | win_system_log_cleared | 0 | Only its two own EVTX samples match; nothing to review. |
| 2026-10-17 | win_psexec_service_installed | 4 (APT29 day 1) | **Attack** (owner confirmed): 4 × `PSEXESVC` installed on NASHUA, 03:11–03:15, the APT29 day 1 PsExec lateral movement. |
| 2026-10-17 | win_psexec_named_pipes | 32 (APT29 day 1) | **Attack** (owner confirmed): the same 4 PsExec runs on NASHUA, each `\PSEXESVC` plus `\PSEXESVC-SCRANTON-<pid>-stdin/stdout/stderr` (created and connected). The pipe names show SCRANTON as the source host. |
| 2026-10-17 | win_renamed_shell_or_lolbin | 0 | Only its two own EVTX samples match. None of the ~35 normal OriginalFileName mismatches in APT29 (Google, Azure agent, Teams, Sysinternals 64-bit builds, Windows binaries) match the targeted list. |
| 2026-10-17 | win_certutil_encode_decode | 1 (APT29 day 2) | **Attack** (owner confirmed): on UTICA, `powershell.exe` runs `certutil -decode blob …\AppData\Roaming\Microsoft\kxwn.lock`, the DLL later loaded by `rundll32 kxwn.lock,VoidFunc` (already a rundll32-rule hit). |
| 2026-10-17 | win_lsass_access_from_user_path | 0 | Only its own PPLdump sample matches. None of the ~1,000 normal LSASS accesses in APT29 (svchost, services, wininit, csrss, wmiprvse, Azure agents) come from a user or network path. |
| 2026-10-17 | *(rejected)* LSASS access with `UNKNOWN` CallTrace frames | — | Investigated, not built: 7 attack hits already caught by the memory-read rule, 2 uncertain APT29 PowerShell `0x1000` hits, and 8 false positives from .NET agents (`AntimalwareConfig.exe`, `WindowsAzureTelemetryService.exe`). |
| 2026-10-17 | win_privileged_builtin_group_member_added | 0 | No hits anywhere: the corpus has no adds to these groups (positives are synthetic). The only other 4732 in the corpus, APT29's new account joining `Builtin\Users` by default, correctly doesn't match. |
| 2026-10-17 | win_domain_admin_group_member_added | 0 | No hits anywhere: the corpus has no adds to these groups (positives are synthetic). The only 4728/4756 in the corpus, APT29's new account joining the local `None` group (RID 513) on SCRANTON by default, correctly doesn't match. |
| 2026-10-17 | win_rundll32_relative_path_dll | 0 | Only its own EVTX samples match (22: the planted `windowscoredeviceinfo.dll` started by the Update Session Orchestrator, `conf3234.dll` and `DATAUS~1.DLL`, `AllTheThings.dll`). APT29's only bare-name rundll32, `AppXDeploymentExtensions.OneCore.dll,ShellRefresh`, is allow-listed. None of the 22 also fires the suspicious-usage rule. |

## AWS CloudTrail

**Corpus:** Invictus IR Sigma-AWS (`CloudTrail/` at commit `f0d5599`, 55 files, Stratus Red Team AWS techniques in one test account), Splunk attack_data (40 raw CloudTrail files at commit `aafa53e`) and OTRF's EC2 proxy S3 exfiltration dataset. 38,793 events, all from lab accounts: every hit is simulated attack activity or lab setup and teardown, so these sources say little about false-positive rates in a real account.

| Date | Rule | Hits outside own samples | Notes |
|---|---|---|---|
| 2026-10-18 | aws_cloudtrail_logging_config_changed | 0 | Only its own samples: the Stratus Red Team `PutEventSelectors` that drops management events and the one restoring it 7 minutes later (Invictus), and `UpdateTrail` (Splunk). |
| 2026-10-18 | aws_cloudtrail_logging_stopped_or_deleted | 7 | Labels confirmed by the owner. Invictus: 2 × `DeleteTrail` by Terraform at 12:08:04 (two different trails, Stratus Red Team cleanup: correct, benign), 1 × failed `DeleteTrail` (`TrailNotFoundException`) by Stratus Red Team (attack simulation). Splunk: `DeleteTrail` by aws-cli in the `update_cloudtrail` dataset (attack simulation); 3 events in `delete_cloudwatch_log_group` are copies of the `stop_delete_cloudtrail` dataset's events (same `eventID`s; attack simulation). |
| 2026-10-18 | aws_root_console_login | 0 | Only its own samples: all 24 root `ConsoleLogin` events in the corpus are in the three Splunk datasets it tests with (8 successful, all without MFA; 16 failed). Invictus has no root activity. |
| 2026-10-18 | aws_root_access_key_used | 0 | No hits: no dataset in the corpus uses a root access key (positives are synthetic). The 11 root API calls in Splunk attack_data all come from console sessions (`ASIA` keys) and correctly don't match. |
| 2026-10-18 | aws_iam_access_key_created_for_other_user | 0 | Only its own samples: the Stratus Red Team backdoor and admin-user keys (Invictus) and the 61 matching `CreateAccessKey` calls in Splunk's T1078 dataset (38 for another named user, 23 by an Okta admin role). The 6 own-key calls in that dataset correctly don't match. |
| 2026-10-18 | aws_iam_admin_policy_granted | 0 | Only its own samples: the two Stratus Red Team AdministratorAccess attaches (Invictus) and Splunk's 3 CreatePolicyVersion (`*` and `iam:*`) and 4 SetDefaultPolicyVersion events. The Stratus setup policies (`AmazonSSMManagedInstanceCore`, narrow inline role policies) correctly don't match. |
| 2026-10-18 | aws_security_group_ingress_open_to_internet | 62 | **Proposed labels, awaiting owner review.** 60 × port 80 opened to 0.0.0.0/0 by the EC2 console launch wizard (`console.ec2.amazonaws.com`) in `abnormally_high_cloud_instances_launched`: correct, benign (public web servers). 2 × in `T1562.007_aws_delete_acl`: the same events as `aws_create_acl` (same `eventID`s; one call opening 22, 3389, WinRM and others, one opening all traffic): attack simulation. |

## Limits of this review

A clean sweep shows the rules are precise on these datasets, not that they're free of false positives in a real fleet. The APT29 background traffic is the only sizeable stretch of normal activity in the corpus, and it comes from a small lab with few third-party tools. Software inventories, EDR agents and management tooling in a real environment will need their own tuning; each triage note lists the expected sources.
