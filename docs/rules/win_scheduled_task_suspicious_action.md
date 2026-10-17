# Scheduled Task Created With Script Host, LOLBin or User-Writable Path Action

| | |
|---|---|
| **Rule** | [`rules/windows/persistence/win_scheduled_task_suspicious_action.yml`](../../rules/windows/persistence/win_scheduled_task_suspicious_action.yml) |
| **Rule ID** | `ceca7f49-e620-45d8-b237-a34766b2b2fa` |
| **Level** | medium |
| **ATT&CK** | Persistence, Execution: T1053.005 Scheduled Task |
| **Log source** | Security 4698 (requires "Audit Other Object Access Events") |

## Summary

A scheduled task was registered whose action runs a command interpreter, script host or common LOLBin, or runs something from a user-writable folder. That covers most malicious task usage: persistence (Empire-style registry-stored payloads), remote execution over ATSVC (atexec-style), and privilege-escalation helpers dropped in `C:\Users\Public`.

## What it detects

Security 4698 where `TaskContent` (the task XML) contains any of:

- **Binaries:** `cmd.exe`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`
- **Paths:** `\Users\Public\`, `\AppData\`, `\Temp\`, `\Downloads\`

Matching is plain text inside `TaskContent`, not XML tags, because some collectors store the XML escaped (`&lt;Command&gt;`) and others don't.

Important: `TaskContent` is the whole task definition, not just the action. A keyword in the task's name (`<URI>`), `<Author>` or `<Description>` also matches.

**Sentinel note:** the KQL targets `SecurityEvent`, which has no `TaskContent` column, so the pipeline maps `TaskContent` to `EventData`. In Sentinel, `EventData` also contains the creating user and the task name as separate fields, so matches there are slightly broader than in Splunk.

Not covered:

- **Tasks that run a renamed or custom binary** from a path not in the list, for example `C:\ProgramData\…` (left out on purpose because it's noisy) or `C:\Windows\` subfolders.
- **COM handler tasks** (`<ComHandler>` instead of `<Exec>`) unless a listed keyword appears elsewhere in the XML.
- **Changes to existing tasks** (4702, Task Updated). This rule only covers creation (4698).
- **Hosts without 4698 auditing.** On those, Sysmon 1 for `schtasks.exe /create`, the TaskScheduler/Operational log (106) and registry writes under `TaskCache` are the alternatives.

## Triage steps

1. **Read the task XML.** Look at `Exec/Command` and `Arguments`, `Principal/UserId` and `RunLevel` (SYSTEM or `HighestAvailable` is worse), and the trigger type (`LogonTrigger` or `BootTrigger` points to persistence). Also check `<Hidden>`.
2. **Check the task name.**
   - Random short names (for example `\CYAlyNSS`) suggest remote execution tooling.
   - Names under `\Microsoft\Windows\…` that are new on the host, created by a user account, or running cmd/PowerShell suggest masquerading. Compare against a known-good host.
3. **Check who created it and from where.** Look at `SubjectUserName` and `SubjectLogonId`, and pivot on the logon ID to 4624. A network logon (type 3) from another host means remote task creation, so look at the source host too.
4. **Decode the payload.** Encoded or registry-stored payloads (`gp HKLM:\…`, `FromBase64String`) mean the next stage is elsewhere. Pull the referenced registry value or file.
5. **Look for execution.** Check 4698 followed quickly by 4699 (deleted), which atexec does after collecting output. Then look for task execution (TaskScheduler 200/201, or Sysmon 1 with parent `svchost.exe -k netsvcs -p -s Schedule` or `taskeng.exe`) and the output files it wrote.
6. **Decide.** A known installer or management tool, at its normal path, created by its own service account, with consistent content across the fleet, can be tuned out. Tasks running encoded or registry-stored PowerShell, binaries from `Users\Public` or `Temp`, or created over the network should be escalated.

## Known false positives

- **Per-user application updaters** that register tasks running from `%LOCALAPPDATA%`, such as some browser, chat and meeting clients. They often show as expanded `\AppData\` paths.
- **Admin, GPO and software-deployment tasks** that wrap scripts in `cmd.exe /c` or PowerShell.
- **Tasks whose name, author or description contains a keyword**, for example "Temp cleanup" or "PowerShell maintenance". This is a known side effect of matching the whole XML.

When tuning, exclude by exact task name (`TaskName`) together with the expected command. Avoid excluding by task name alone, because attackers reuse legitimate-looking names (see the `SoftwareProtectionPlatform\EventCacheManager` sample).

## Related techniques

- **T1036.004 Masquerade Task or Service:** tasks named like built-in Windows tasks.
- **T1021.002 SMB/Windows Admin Shares:** remote task creation over ATSVC usually follows SMB authentication to the target.
- **T1112 Modify Registry:** payloads stored in registry values and read back by the task (Empire pattern).
- **T1134 Access Token Manipulation:** tasks used to regain privileges for service accounts (FullPowers sample).
- **T1569.002 Service Execution:** the other common remote-execution path; check for 7045 on the same host and time.
- **T1047 Windows Management Instrumentation:** an alternative remote execution route; compare if 4698 is missing.
