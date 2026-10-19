# Shadow Copies, Backup Catalog or Boot Recovery Deleted or Disabled

| | |
|---|---|
| **Rule** | [`rules/windows/impact/win_inhibit_system_recovery.yml`](../../rules/windows/impact/win_inhibit_system_recovery.yml) |
| **Rule ID** | `7f9450cf-5f57-4f8c-8ee9-8e28c88d5077` |
| **Level** | high |
| **ATT&CK** | Impact: T1490 Inhibit System Recovery |
| **Log source** | Process creation (Sysmon 1 / Security 4688) |

## Summary

A built-in Windows tool removed local recovery options: shadow copies deleted or purged, the backup catalog or backups deleted, or Windows recovery and boot failure handling turned off. Ransomware does this just before (or while) encrypting, so the victim can't roll back. Treat a hit as a possible encryption event in progress until shown otherwise.

## What it detects

Process creation where the binary and the action both match:

| Binary (`Image` ends with) | Command line contains |
|---|---|
| `\vssadmin.exe` | `delete` + `shadows`, or `resize` + `shadowstorage` (shrinking the storage purges shadow copies) |
| `\wmic.exe` | `shadowcopy` + `delete` |
| `\powershell.exe`, `\pwsh.exe` | `win32_shadowcopy` + one of `.delete(`, `remove-ciminstance`, `remove-wmiobject` |
| `\wbadmin.exe` | `delete` + `catalog` or `backup` (includes `systemstatebackup`) |
| `\bcdedit.exe` | `recoveryenabled` + ` no`, or `bootstatuspolicy` + `ignoreallfailures` |

Matching on the binary means a `cmd /c "vssadmin delete shadows ..."` wrapper isn't counted as a second hit.

Not covered:

- **Renamed copies of these tools.** `OriginalFileName` isn't used, because Sentinel's `SecurityEvent` doesn't have it (see the renamed-binary rule, which also lacks Sentinel for that reason).
- **Encoded or obfuscated PowerShell** (`-enc`, string concatenation such as `'Win32_Shadow'+'Copy'`): see the encoded-PowerShell rule.
- **Deletion through the VSS API or WMI from other processes** (for example ransomware calling `IVssBackupComponents` directly, or WMI from a .NET binary), and `diskshadow` scripts (`diskshadow /s file.txt` hides the commands in the file).
- **Other boolean spellings** for `recoveryenabled` (`off`, `false`) and quoted values.
- **Other recovery-impairing steps:** deleting backup files directly, stopping the VSS or backup services, or disabling Windows RE with `reagentc /disable`.

## Triage steps

1. **Assume impact is near.** Check the same host for signs of encryption in the minutes around the hit: mass file renames or writes (Sysmon 11/23), ransom notes, unusual extensions, and the same commands on other hosts. Several hosts in a short time means a deployed payload (GPO, PsExec, scheduled task): start incident response, don't finish the triage first.
2. **Parent and process chain.** Which process ran the tool (`cmd` or PowerShell under an unknown binary, a script from `Temp`/`ProgramData`/`Users\Public`, a service, PsExec, WMI)? Backup or imaging software as the parent points to benign maintenance.
3. **User and logon.** Was it run by a known admin from their usual workstation, or by a service or freshly used account, or over a remote logon (4624 type 3/10) shortly before?
4. **What came before.** Look for the usual ransomware lead-up on this host: credential dumping, security tools stopped, event logs cleared, AV exclusions, mass network share access.
5. **Decide.** A planned cleanup by a known backup tool or admin, with a change record, can be tuned by exact command line and parent. Anything else is an incident: isolate the host and check for spread.

## Known false positives

- **Admins resizing shadow storage** or deleting old shadow copies or backups to free disk space.
- **Backup or imaging software** managing its own shadow copies or catalog.
- **OS deployment or kiosk/VDI image scripts** that turn off recovery or boot failure handling (`bcdedit`).

Tune by parent process and exact command line, not by binary name.

## Related techniques

- **T1486 Data Encrypted for Impact:** the encryption this step usually precedes.
- **T1685.005** (event log clearing, see the log-cleared rules): often in the same ransomware script.
- **T1047 Windows Management Instrumentation:** wmic and `Win32_ShadowCopy` access.
- **T1059.001 PowerShell / T1059.003 Windows Command Shell:** how these commands are usually launched.
- **T1003.003 NTDS:** shadow copies are also *created* to copy `NTDS.dit` (the hive and NTDS dumping rule); this rule only looks for removal.
