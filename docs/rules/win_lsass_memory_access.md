# LSASS Process Opened With Memory Read Access

| | |
|---|---|
| **Rule** | [`rules/windows/credential_access/win_lsass_memory_access.yml`](../../rules/windows/credential_access/win_lsass_memory_access.yml) |
| **Rule ID** | `dcb8f47e-4cf7-48fc-9bef-8c5b346ce80c` |
| **Level** | high |
| **ATT&CK** | Credential Access: T1003.001 OS Credential Dumping: LSASS Memory |
| **Log source** | Sysmon Event ID 10 (ProcessAccess) |

## Summary

A process opened `lsass.exe` with rights that allow reading its memory. That's the prerequisite for dumping credentials from LSASS, whether with a dump file (ProcDump, Task Manager, Dumpert) or by reading memory in place (Mimikatz, Invoke-Mimikatz).

## What it detects

Sysmon 10 events where:

- `TargetImage` ends with `\lsass.exe`, and
- `GrantedAccess` is one of `0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1f0fff`, `0x1f1fff`, `0x1f3fff`, `0x1fffff`. Every mask in the list includes `PROCESS_VM_READ` (0x10).

Excluded by exact path: `services.exe`, `wininit.exe` and `csrss.exe` in `C:\Windows\System32\`.

Not covered:

- **Other access masks.** A tool that requests a read mask not in the list won't fire. The list is a starting point, not an exhaustive bitmask check, which Sigma can't express.
- **Tools that don't need a read handle.** PPLdump, for example, requests only `0x1000` and reaches LSASS another way. The rule [LSASS Opened by a Process From a User or Network Path](win_lsass_access_from_user_path.md) covers that case when the tool runs from a user, temp or network path.
- **CallTrace indicators** (`dbghelp.dll`, `dbgcore.dll`, `UNKNOWN(`) are deliberately not used. Against the test data they added no detections the access masks didn't already catch. A separate `UNKNOWN`-frame rule was investigated in M2 and rejected: across the sweep corpus it added 2 uncertain hits against 8 false positives from .NET agents (Azure antimalware and telemetry), because JIT-compiled .NET code, PowerShell included, also shows as `UNKNOWN`. The frames are still useful in triage (step 4).
- **Hosts whose Sysmon config doesn't log ProcessAccess to `lsass.exe`.** Check this before trusting silence from this rule.

## Triage steps

1. **Identify the source process.** Check `SourceImage`, its path, signer and hash. Anything outside `Program Files` or `System32`, unsigned, or with a renamed binary is a strong signal. Note the `GrantedAccess` value: `0x1fffff` (full access) together with a dump-capable tool usually means a dump file.
2. **Get the process tree.** Pivot on `SourceProcessGUID` to the Sysmon 1 process-creation event: command line, parent, user and integrity level. Look for `procdump -ma lsass`, `rundll32 ... comsvcs.dll MiniDump`, `sekurlsa::`, or a PowerShell host with encoded or downloaded content.
3. **Look for a dump file.** Check Sysmon 11 (FileCreate) from the same process within a few minutes, especially `.dmp` files or odd names in `Temp`, `ProgramData` or user profile directories.
4. **Check the CallTrace.** `dbghelp.dll` or `dbgcore.dll` points to MiniDumpWriteDump. `UNKNOWN(...)` frames point to code running from unbacked memory: injected code or a reflectively loaded tool.
5. **Scope.** Search for the same `SourceImage` hash or name, and the same user, on other hosts. Check for follow-on use of credentials from this host: new logons (4624 type 3/10) from it, pass-the-hash patterns, or access to new systems by accounts that were logged on here.
6. **Decide.** A known, signed security or backup agent at its expected path, with a consistent history across the fleet, can be tuned out (see below). Anything else, including an admin dumping LSASS without a change record, should be escalated: assume credentials on the host are exposed and start credential resets for accounts with active sessions.

## Known false positives

- **AV, EDR and backup agents** that scan or snapshot LSASS. These are environment-specific and are intentionally not excluded in the rule. Tune them locally by exact path, and by signer if your SIEM has it, never by file name alone.
- **Administrators troubleshooting LSASS** with Task Manager or ProcDump. The activity is real; it's a policy question whether it's allowed. Confirm with the admin and the change record.
- **Monitoring or inventory tools** that read process memory.
- **Note on the system-process filter:** the `services.exe` exclusion is based on events seen in the public EVTX-ATTACK-SAMPLES PPLdump recording, not on a clean baseline. One of those `services.exe` events requested `0x1fffff` with `dbgcore.dll` in its call trace, which looks like a dump rather than routine access. The exclusion keeps the rule quiet for normal service-control activity, but `services.exe` opening LSASS with full access plus a dump-related call trace is worth its own look. If that pattern shows up in your environment, narrow the filter (for example, to specific access masks) instead of excluding the process outright.

## Related techniques

- **T1003.001 LSASS Memory:** the technique this rule targets.
- **T1055 Process Injection:** in-memory dumpers often run injected or reflectively loaded code, which shows as `UNKNOWN` frames in the CallTrace.
- **T1059.001 PowerShell:** Invoke-Mimikatz and similar run inside `powershell.exe`, so the source process alone won't look malicious.
- **T1218.011 Rundll32:** `rundll32.exe` loading `comsvcs.dll` (`MiniDump` export) or a custom DLL, as in the Dumpert DLL sample.
- **T1550.002 Pass the Hash:** a common next step once NTLM hashes are recovered from LSASS.
