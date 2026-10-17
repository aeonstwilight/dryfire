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

## Limits of this review

A clean sweep shows the rules are precise on these datasets, not that they're free of false positives in a real fleet. The APT29 background traffic is the only sizeable stretch of normal activity in the corpus, and it comes from a small lab with few third-party tools. Software inventories, EDR agents and management tooling in a real environment will need their own tuning; each triage note lists the expected sources.
