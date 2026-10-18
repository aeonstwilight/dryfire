# PsExec-Style Named Pipes Created or Connected

| | |
|---|---|
| **Rule** | [`rules/windows/lateral_movement/win_psexec_named_pipes.yml`](../../rules/windows/lateral_movement/win_psexec_named_pipes.yml) |
| **Rule ID** | `1aac3869-250d-4f3b-8957-86a466a5329a` |
| **Level** | medium |
| **ATT&CK** | Lateral Movement: T1021.002 SMB/Windows Admin Shares; Execution: T1569.002 Service Execution |
| **Log source** | Sysmon 17/18 (Pipe Created / Pipe Connected) |

## Summary

A process created or connected to PsExec's named pipes: the `\PSEXESVC` control pipe, or the per-session I/O pipes `\<service>-<host>-<pid>-stdin`, `-stdout` and `-stderr`. The I/O pipe suffixes stay the same when PsExec is renamed with `-r`, so this rule sees **renamed PsExec**, which the 7045 service rule can't.

**Prioritise renamed pipes.** If the part before `-<host>-<pid>-` isn't `PSEXESVC` (for example `\svchost-MSEDGEWIN10-8116-stdin` or `\blabla-NLLT108334-37048-stdin`), someone went out of their way to hide PsExec. Admins rarely bother to rename it. Treat that as high priority whatever the source.

## What it detects

Sysmon 17 or 18 where `PipeName` is exactly `\PSEXESVC`, or ends with `-stdin`, `-stdout` or `-stderr`.

The pipe name tells you more than the rule condition shows:

- `\PSEXESVC-<host>-<pid>-stdin`: original PsExec. `<host>` is the **source** machine and `<pid>` is the `PsExec.exe` process ID there.
- `\<other>-<host>-<pid>-stdin`: renamed PsExec (`-r <other>`). The source host and PID are still in the name.
- `\PSEXESVC` with no I/O pipes: often local `-s` use for SYSTEM, or a session that didn't open standard I/O.

On the **target**, the `Image` creating the pipes (17) is the service binary (`C:\Windows\PSEXESVC.exe` or `C:\Windows\<other>.exe`). On the **source**, the `Image` connecting (18) is `PsExec.exe`.

In the full test corpus, the only pipes with these suffixes are PsExec's own.

Not covered:

- **Hosts without Sysmon pipe logging** (Event IDs 17/18 must be enabled in the Sysmon config). Security 5145 on `IPC$` with the same `RelativeTargetName` pattern is the alternative. It's a candidate follow-up rule, held for now because detailed file share auditing is rarely enabled.
- **Tools with different pipe schemes:** Impacket `psexec.py` / RemCom (`\RemCom_communicaton` and similar), PAExec, Metasploit psexec.

## Triage steps

1. **Original or renamed.** Look at the pipe prefix. Anything other than `PSEXESVC` gets the high-priority path described above.
2. **Source and target.** Read the `<host>` and `<pid>` from the pipe name for the source. On the target, look at the service binary path and the 7045 for the renamed service name, which the suspicious-service rule may also have caught. Then pivot to 4624 type 3 and 5145 (`ADMIN$`, `IPC$`) on the target.
3. **What it ran.** Look at child processes of the service binary on the target (Sysmon 1) and the `PsExec.exe` command line on the source.
4. **Scope.** Search for the same prefix, source host or source PID across all hosts. One PsExec process usually fans out.
5. **Decide.** Original `PSEXESVC` from a known admin host, by an admin account, can be closed as admin use. Renamed pipes, unexpected sources, or suspicious child processes should be escalated as lateral movement.

## Known false positives

- **Administrators and IT tooling** using Sysinternals PsExec, original or renamed. Renamed use by admins does happen, but rarely.
- **Other remote-execution tools** that copy PsExec's pipe naming scheme.

Tune by source host and account. Don't tune by pipe prefix, because attackers pick prefixes that look legitimate (`svchost`, `update`).

## Related techniques

- **T1036.004 Masquerade Task or Service:** renamed PsExec services named after real services.
- **T1570 Lateral Tool Transfer:** the service binary copied to `ADMIN$`.
- **T1543.003 Windows Service:** the matching 7045 service install on the target.
- **T1078 Valid Accounts:** PsExec needs admin credentials on the target.
