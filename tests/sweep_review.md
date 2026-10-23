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
| 2026-10-18 | aws_security_group_ingress_open_to_internet | 62 | Labels confirmed by the owner (2026-10-18). 60 × port 80 opened to 0.0.0.0/0 by the EC2 console launch wizard (`console.ec2.amazonaws.com`) in `abnormally_high_cloud_instances_launched`: correct, benign (public web servers). 2 × in `T1562.007_aws_delete_acl`: the same events as `aws_create_acl` (same `eventID`s; one call opening 22, 3389, WinRM and others, one opening all traffic): attack simulation. |
| 2026-10-18 | aws_s3_public_access_block_disabled | 0 | Only its own samples: the two `PutBucketPublicAccessBlock` calls with all protections off before the public policy in Splunk's T1485 dataset. |
| 2026-10-18 | aws_s3_bucket_made_public | 0 | Only its own samples: 8 public ACLs (2 AllUsers, 6 AuthenticatedUsers) in Splunk's T1530 dataset and the 2 `Principal: *` policies in T1485. The Stratus Red Team cross-account backdoor policy and the CloudTrail log-bucket policies correctly don't match. |
| 2026-10-18 | aws_guardduty_disabled | 0 | Only its own samples: the 2 failed `DeleteDetector` calls in Splunk's T1562.008 `aws_delete_security_services`. The Invictus GuardDuty read calls (`ListDetectors`, `ListFindings`) correctly don't match. |
| 2026-10-18 | aws_guardduty_findings_suppressed | 0 | Only its own samples: the failed `DeleteIPSet` call in the same Splunk dataset. |
| 2026-10-18 | aws_secretsmanager_many_secrets_read | 0 | Counted per identity over the threshold, not per event. Only its own sample: the Stratus Red Team retrieve-secrets run in Invictus (one user, 20 secrets in 4 seconds). The same user's other reads in the Invictus files (at most 7 distinct secrets per file) don't add a second hit. |
| 2026-10-19 | aws_network_acl_ingress_open_to_internet | 5 | Labels confirmed by the owner (2026-10-19). 5 own-sample hits in `T1562.007_aws_create_acl` and the same 5 events (same `eventID`s) in `T1562.007_aws_delete_acl`: attack simulation (all traffic, port 22 and wide port ranges allowed in from 0.0.0.0/0), the same events labelled for the security group rule. The Invictus `DescribeNetworkAcls` reads correctly don't match. |
| 2026-10-19 | aws_s3_bucket_policy_cross_account_access | 0 | Only its own sample: the Stratus Red Team backdoor policy in Invictus (account 193672423079's root granted GetObject and ListBucket). The CloudTrail log-bucket policies (service principals) and the public `Principal: *` policy correctly don't match. |
| 2026-10-19 | win_password_spray_from_one_source | 0 | No hits. The Windows corpus has almost no failed logons (one local 4625; two 4771s from one address in `kerberos_pwd_spray_4771`, below the threshold), so this sweep says little about noise in real environments. |
| 2026-10-19 | win_brute_force_one_account_from_one_source | 0 | No hits. As for the spray rule, the Windows corpus has almost no failed logons, so this says little about noise in real environments. |
| 2026-10-19 | win_inhibit_system_recovery | 0 | Only its own sample: the four Atomic Red Team T1490 commands in `PanacheSysmon_vs_AtomicRedTeam01` (vssadmin delete shadows, wbadmin delete catalog, two bcdedit changes), each counted once although it runs under a `cmd /c` wrapper. `vssadmin list shadows` and `wmic shadowcopy call create` in `sysmon_exec_from_vss_persistence` and `vssadmin create shadow` in Panache correctly don't match. |
| 2026-10-20 | win_dcsync_replication_by_non_machine_account | 0 | Only its own sample: the Get-Changes-All event of the Mimikatz DCSync in `CA_DCSync_4662` (its two plain Get-Changes events don't count). The DC machine accounts' replication (`DC1$` in `ACL_ForcePwd_SPNAdd_User_Computer_Accounts`, `NEWYORK$` in APT29 day 1, Get-Changes only) correctly doesn't match. |
| 2026-10-20 | win_sam_security_hive_or_ntds_dumped | 0 | Only its own sample: the 7 Atomic Red Team `reg save` commands (SAM, SECURITY, SYSTEM) and the 2 `copy` commands of NTDS.dit and SYSTEM out of `HarddiskVolumeShadowCopy1` in `PanacheSysmon_vs_AtomicRedTeam01`; the `cmd /c` wrappers around `reg save` correctly don't count. The payload run from a shadow copy in `sysmon_exec_from_vss_persistence` and `remote_sam_registry_access_via_backup_operator_priv` (remote registry, no process on the target) correctly don't match. |
| 2026-10-20 | win_wmi_event_subscription_code_consumer | 1 (APT29 day 2) | **Attack** (owner agreed, 2026-10-20): on UTICA (user dschrute), the APT29 persistence step binds `__EventFilter` "WindowsParentalControlMigration" (`Win32_LoggedOnUser` creation) to a `CommandLineEventConsumer` running `powershell -exec bypass -Noninteractive -windowstyle hidden -e …`. Own samples: Atomic Red Team (Panache), `sysmon_20_21_1_CommandLineEventConsumer` and `wmighost_sysmon_20_21_1` (one each; their later `Deleted` bindings correctly don't count). |
| 2026-10-20 | aws_kms_key_disabled_or_deletion_scheduled | 0 | Only its own sample: `ScheduleKeyDeletion` (7 days) and `DisableKey` in Splunk's T1486 `aws_kms_key` console session. The same session's `CreateKey`, `PutKeyPolicy`, `CancelKeyDeletion` and `EnableKey`, and the `CreateKey` calls in other datasets, correctly don't match. |
| 2026-10-21 | aws_iam_user_console_login_without_mfa | 0 | Only its own samples: the 2 Atomic Red Team console logins after `CreateLoginProfile` (Splunk T1078) and the Stratus Red Team user's login (Invictus). bert-jan's login with MFA, the failed IAM user logins (MFAUsed No), root logins and the 122 federated `AssumedRole` logins correctly don't match. |
| 2026-10-21 | aws_iam_mfa_device_deactivated | 0 | Only its own sample: root deactivating its own MFA device in Splunk's T1621 `aws_mfa_disabled` (the `DeleteVirtualMFADevice` right after correctly doesn't count). The `CreateVirtualMFADevice` calls in the T1556.006 dataset correctly don't match. |
| 2026-10-21 | aws_ec2_or_rds_snapshot_shared_outside_account | 0 | Only its own samples: Splunk's T1537 snapshot shares (6, including a call rejected for an invalid account ID and a share with `all`) and AMI shares (2, one public), and the Stratus Red Team AMI, EBS snapshot and RDS snapshot shares in Invictus (3). Their revokes (`remove`, `valuesToRemove`) and the empty `add` correctly don't match. |
| 2026-10-23 | aws_iam_login_profile_created_or_updated | 0 | Only its own samples: Atomic Red Team's `CreateLoginProfile` (3) and `UpdateLoginProfile` (2) for user AtomicRedTeam in Splunk's T1078 datasets, and the two Stratus Red Team users given a console password in Invictus. The account password-policy changes in T1201 correctly don't match. |
| 2026-10-23 | aws_s3_bucket_versioning_suspended | 0 | Only its own sample: Splunk's T1490 `PutBucketVersioning` with `Status: Suspended` on bucket git-wild-hunt-results (one event, stored twice in the file, so 2 hits). The `GetBucketVersioning` reads in Invictus correctly don't match. |
| 2026-10-23 | aws_ssm_send_command_run_script | 0 | Only its own samples: Stratus Red Team's two `SendCommand` calls with `AWS-RunShellScript` by bert-jan in Invictus (one failed with `InvalidInstanceId`). `GetCommandInvocation` and association status updates correctly don't match. |
| 2026-10-23 | win_run_key_script_or_user_path_value | 1 (APT29 day 2) | **Attack** (to be confirmed by the owner): on UTICA (user dschrute), powershell.exe sets HKCU `Run\WebCache` to `rundll32.exe C:\Users\dschrute\AppData\Roaming\Microsoft\kxwn.lock,VoidFunc`, the APT29 day 2 persistence step. Otherwise only its own 6 EVTX samples. Defender's `Run\WindowsDefender` (MsMpEng.exe, Program Files) and Teams' `Update.exe` in `AppData\Local` correctly don't match. |

## Limits of this review

A clean sweep shows the rules are precise on these datasets, not that they're free of false positives in a real fleet. The APT29 background traffic is the only sizeable stretch of normal activity in the corpus, and it comes from a small lab with few third-party tools. Software inventories, EDR agents and management tooling in a real environment will need their own tuning; each triage note lists the expected sources.
