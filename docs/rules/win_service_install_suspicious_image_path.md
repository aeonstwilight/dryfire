# Service Installed With Shell, Named Pipe, User-Folder or Path-Less Image Path

| | |
|---|---|
| **Rule** | [`rules/windows/persistence/win_service_install_suspicious_image_path.yml`](../../rules/windows/persistence/win_service_install_suspicious_image_path.yml) |
| **Rule ID** | `766335a9-08be-4da8-b038-aeb703bc5442` |
| **Level** | high |
| **ATT&CK** | Persistence, Privilege Escalation: T1543.003 Windows Service; Execution: T1569.002 Service Execution |
| **Log source** | System 7045 (Service Control Manager) |

## Summary

A new service was installed whose `ImagePath` doesn't look like a real service binary. It runs a shell or script host, writes to a named pipe, runs from a user folder, or has no path at all. This is how PsExec-style remote execution (Empire psexec, smbexec, Impacket-style tooling), remote service creation and getsystem-style named-pipe privilege escalation show up in the System log.

## What it detects

System 7045 where `ImagePath` matches any of:

- **Interpreter / LOLBin:** contains `cmd.exe`, `%COMSPEC%`, `powershell`, `pwsh`, `mshta`, `rundll32`, `regsvr32`, `wscript` or `cscript`.
- **Named pipe:** contains `\pipe\`, as in `cmd /c echo … > \\.\pipe\<name>`, the classic service-based token-impersonation trick.
- **User folder:** contains `\Users\`, `\AppData\` or `\Temp\`.
- **No path:** contains no backslash at all (for example `cmd.exe` or `calc.exe`). Real services are registered with a full path, `%SystemRoot%\…`, `\SystemRoot\…` or `System32\drivers\…`.

`\ProgramData\` is deliberately not in the list: security products install drivers and services there (the negative test includes a real Defender driver from `ProgramData`).

Not covered:

- **Implants dropped at a clean system path.** For example, Covenant's `GruntHTTP2.exe` in `C:\Windows\System32` under a short service name. Catching this needs new-binary-in-`System32` detection (Sysmon 11, file creation) or hash and name intel.
- **Plain PsExec** (`PSEXESVC`, `%SystemRoot%\PSEXESVC.exe`). Left out by design, because admins use it legitimately. It's a candidate for its own lower-severity rule, which should also handle renamed PsExec.
- **Services created without a 7045 event**, for example by writing directly to the registry under `HKLM\SYSTEM\CurrentControlSet\Services`. Sysmon 12/13 covers that.
- **Changes to existing services**, such as changing the `ImagePath` of a service that already exists. That shows as 7040 or registry changes, not 7045.

## Triage steps

1. **Read the `ImagePath`.** Decode any encoded PowerShell (see the triage note for the encoded PowerShell rule). A nested `%COMSPEC% /C "%COMSPEC% /C start /b …"` is typical of smbexec-style tooling, and `echo … > \\.\pipe\…` is named-pipe impersonation.
2. **Check the service name.** Random strings (for example `PGUJLOAKFQFVOMHGFQPX`), short throwaway names, or names copying real services (`spoolsv`, `Updater`) on a host where they don't belong are all signals. Check `StartType`: demand start plus immediate deletion is typical of one-shot remote execution.
3. **Find the source.** 7045 doesn't record who installed the service. Pivot to Security 4624 type 3 logons and 5140/5145 (`ADMIN$`, `IPC$`, `svcctl` pipe) on the same host in the minute before, then to the source host.
4. **Look for execution and cleanup.** Sysmon 1 with parent `services.exe` running the `ImagePath` command, then the service being deleted (7036 stop or the registry key removed). Output files in `ADMIN$`, `C$\Windows\Temp` or the named pipe point to the tooling.
5. **Scope.** Search for the same service name or `ImagePath` pattern across hosts. Lateral movement tooling usually hits several hosts from one source.
6. **Decide.** Very little legitimate software installs a service like this. A known, documented installer can be tuned out by exact service name together with the exact `ImagePath`. Anything with encoded PowerShell, a pipe redirect or a path-less binary should be escalated as likely lateral movement or privilege escalation.

## Known false positives

- **Management and installer tooling** that registers a service wrapping `cmd.exe /c` or PowerShell. This is uncommon and should be documented when it happens.
- **Per-user software** that installs a service from the user profile, for example some VPN, remote-support or game anti-cheat clients.

Tune by exact `ServiceName` plus exact `ImagePath`, never by service name alone, because attacker tooling reuses believable names.

## Related techniques

- **T1021.002 SMB/Windows Admin Shares:** remote service creation goes over SMB (`ADMIN$` and the `svcctl` pipe).
- **T1570 Lateral Tool Transfer:** the service binary is often copied to `ADMIN$` just before.
- **T1134.001 Token Impersonation/Theft:** named-pipe services used to impersonate SYSTEM.
- **T1036.004 Masquerade Task or Service:** service names copying legitimate ones.
- **T1059.001 PowerShell:** encoded PowerShell as the service payload.
