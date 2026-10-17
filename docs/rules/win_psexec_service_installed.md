# PsExec Service Installed

| | |
|---|---|
| **Rule** | [`rules/windows/lateral_movement/win_psexec_service_installed.yml`](../../rules/windows/lateral_movement/win_psexec_service_installed.yml) |
| **Rule ID** | `9e2dd760-c1e9-4385-8256-ad0c7efc5f21` |
| **Level** | medium |
| **ATT&CK** | Lateral Movement: T1021.002 SMB/Windows Admin Shares; Execution: T1569.002 Service Execution |
| **Log source** | System 7045 (Service Control Manager) |

## Summary

The Sysinternals PsExec service (`PSEXESVC`) was installed on this host. That means someone ran PsExec against it, either remotely over SMB or locally with `-s` to get SYSTEM. PsExec is a legitimate admin tool and a favourite of attackers and ransomware operators for the same reason, so the question is always who ran it, from where, and what it launched.

## What it detects

System 7045 where `ServiceName` is `PSEXESVC` or `ImagePath` ends with `\PSEXESVC.exe` (normally `%SystemRoot%\PSEXESVC.exe`).

Not covered:

- **Renamed PsExec** (`psexec -r <name>`). Both the service name and the image path change to `<name>`, so 7045 alone can't tell it from any other service. The PsExec named-pipe rule covers this through the `-stdin`/`-stdout`/`-stderr` pipe names.
- **PsExec look-alikes** (Impacket `psexec.py`, Empire and Metasploit psexec modules, PAExec, RemCom) that install their own service names. The suspicious-service rule catches many of these through their image paths (`%COMSPEC%`, encoded PowerShell, path-less binaries).

## Triage steps

1. **Who ran it and from where.** 7045 doesn't record the source. Pivot to Security 4624 type 3 on this host just before, and its source IP and account, then to 5145 for `ADMIN$` (where `PSEXESVC.exe` is copied) and `IPC$` (the `PSEXESVC` pipes).
2. **What it ran.** Look at Sysmon 1 child processes of `PSEXESVC.exe`: the command PsExec executed. Interactive `cmd.exe`, credential dumping, `vssadmin delete shadows`, or encryption tools are high-signal.
3. **Local or remote.** No inbound network logon plus `PsExec.exe` running locally, often with `-s`, means local privilege escalation to SYSTEM rather than lateral movement.
4. **Scope.** Search for 7045 `PSEXESVC` across the fleet in the same window. Ransomware staging often pushes PsExec to many hosts within minutes from one source.
5. **Decide.** Known admin use, from an admin workstation or jump host, by an admin account, on a ticket, can be closed. PsExec from a user workstation, by a service account, at odd hours, or running unusual commands should be escalated.

## Known false positives

- **Administrators and IT tooling** using Sysinternals PsExec for remote administration, software deployment or troubleshooting.

Tune by source host and account (your admin jump hosts and admin accounts), never by the target. If PsExec is banned in your environment, raise the level instead.

## Related techniques

- **T1570 Lateral Tool Transfer:** `PSEXESVC.exe` is copied to `ADMIN$` before the service is installed.
- **T1543.003 Windows Service:** the service install itself.
- **T1036.004 Masquerade Task or Service:** renamed PsExec (`-r`) choosing a service name like `svchost` or `update`.
- **T1078 Valid Accounts:** PsExec needs admin credentials on the target, so check how the account was obtained.
