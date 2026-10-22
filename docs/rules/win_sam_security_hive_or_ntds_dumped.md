# SAM or SECURITY Hive, or NTDS.dit, Copied for Offline Credential Extraction

| | |
|---|---|
| **Rule** | [`rules/windows/credential_access/win_sam_security_hive_or_ntds_dumped.yml`](../../rules/windows/credential_access/win_sam_security_hive_or_ntds_dumped.yml) |
| **Rule ID** | `f15cf7d7-0c1a-4350-84e4-acf1ff5223ea` |
| **Level** | high |
| **ATT&CK** | Credential Access: T1003.002 Security Account Manager, T1003.003 NTDS, T1003.004 LSA Secrets |
| **Log source** | Process creation (Sysmon 1 / Security 4688) |

## Summary

A built-in tool copied a credential store so it can be cracked offline: the SAM hive (local account hashes), the SECURITY hive (LSA secrets, cached domain logons), the SYSTEM hive (the boot key needed to decrypt both), or the AD database `ntds.dit` (every domain hash). On a domain controller this is domain-wide credential theft. The copy is usually followed by moving the files off the host and running `secretsdump` or similar.

## What it detects

Process creation matching any of:

| Selection | Binary (`Image` ends with) | Command line |
|---|---|---|
| reg | `\reg.exe` | ` save ` or ` export `, plus `HKLM\SAM` or `HKLM\SECURITY` (any subkey; also `HKEY_LOCAL_MACHINE\…`), or `HKLM\SYSTEM` as the whole hive only (followed by a space or quote, or at the end) |
| ntdsutil | `\ntdsutil.exe` | `ifm` |
| esentutl | `\esentutl.exe` | `/vss` (any dash style), plus `config\sam`, `config\security`, `config\system` (whole file) or `ntds.dit`, either slash |
| shadow copy | any | `HarddiskVolumeShadowCopy` plus `\ntds.dit`, `\config\sam`, `\config\security` or `\config\system` (whole file) |

- SYSTEM is matched only as the whole hive or file, so `reg export HKLM\SYSTEM\CurrentControlSet\Services\…` and paths under `config\systemprofile` stay quiet.
- The shadow-copy selection has no binary condition because `copy` is a cmd built-in: the command only shows on cmd's own command line. If a separate copy tool (`robocopy`, `xcopy`) runs under a `cmd /c` wrapper, both processes match and the alert counts twice (owner decision).

Not covered:

- **In-memory extraction:** Mimikatz `lsadump::sam`/`lsadump::secrets`, or reading the hives through the registry API from a custom tool.
- **Raw-disk readers** (Invoke-NinjaCopy, raw NTFS parsers) and `diskshadow` scripts (`diskshadow /s file.txt` hides the commands in the file).
- **Renamed copies** of reg, ntdsutil or esentutl (no `OriginalFileName`, as Sentinel's `SecurityEvent` doesn't have it). The robustness check confirms it (`binary_renamed`: 3/21; only the shadow-copy selection, which has no binary condition, still fires). The renamed-binary rule (`win_renamed_shell_or_lolbin`) catches renamed reg, ntdsutil and esentutl by `OriginalFileName` on Splunk, Defender and Elastic (added 2026-10-22); Sentinel has no such column.
- **Creating the shadow copy** (`vssadmin create shadow`, `wmic shadowcopy call create`) on its own: common and benign; only the copy out of it is matched.
- **Remote hive access** over the Remote Registry service (for example `secretsdump` against a remote host): no process on the target. Look for `winreg` named-pipe access (5145) instead.

## Triage steps

1. **What was copied, and where to.** Read the target path. Output in `Temp`, `ProgramData`, `Users\Public`, a share, or with a disguised name (`sam.hive`, `s.dat`) points to theft. Check whether SYSTEM was taken in the same few minutes: SAM or SECURITY without SYSTEM can't be decrypted, so the attacker usually takes both.
2. **Host role.** `ntds.dit` or `ntdsutil ifm` on a DC means every domain hash is exposed. SAM/SECURITY on a server or workstation exposes local admin hashes (often reused) and cached domain credentials.
3. **Parent, user and logon.** A remote session (PsExec, WMI, WinRM, a service), an unusual admin account, or a web server or Office parent are high signal. A known backup or imaging tool under its service account points to benign.
4. **What happened to the files.** Look for archiving (`7z`, `rar`, `Compress-Archive`), file writes to shares, outbound transfers, and deletion of the copies (Sysmon 11/23, 5145).
5. **Follow-on use.** New logons with the local Administrator or other local accounts from this host to others (pass-the-hash), or Kerberos activity with privileged accounts from unusual hosts after an NTDS copy.
6. **Decide.** Treat an unexplained copy as credential compromise: reset local admin passwords (or rotate LAPS), the affected domain accounts, and after an NTDS copy `krbtgt` twice. Tune only known backup or IR tooling, by exact command line, parent and account.

## Known false positives

- **Backup or imaging tools** that copy registry hives or the AD database with a known service account.
- **Install from media (IFM):** admins running `ntdsutil ifm` to promote a new DC. This should be rare and planned.
- **Forensic or IR collection** of registry hives.

## Related techniques

- **T1003.006 DCSync:** the online route to the same domain hashes (the DCSync rule).
- **T1003.001 LSASS Memory:** the other main route to local credentials (the LSASS access rules).
- **T1490 Inhibit System Recovery:** shadow copies are also deleted by ransomware (the recovery-deletion rule); here they are used to read locked files.
- **T1550.002 Pass the Hash:** the usual use of local admin hashes taken from SAM.
- **T1569.002 Service Execution:** PsExec `-s` is a common way to run `reg save` as SYSTEM (OTRF's LSA secrets dataset).
