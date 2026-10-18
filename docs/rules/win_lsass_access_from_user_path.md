# LSASS Opened by a Process From a User or Network Path

| | |
|---|---|
| **Rule** | [`rules/windows/credential_access/win_lsass_access_from_user_path.yml`](../../rules/windows/credential_access/win_lsass_access_from_user_path.yml) |
| **Rule ID** | `9f96c1ba-b381-436d-9c3c-858dfc7f10ed` |
| **Level** | high |
| **ATT&CK** | Credential Access: T1003.001 OS Credential Dumping: LSASS Memory |
| **Log source** | Sysmon Event ID 10 (ProcessAccess) |

## Summary

A process running from a user folder, temp or data folder, or a network share opened `lsass.exe` with an access mask that the LSASS memory-read rule doesn't cover, such as `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION`). Tools like PPLdump don't need a read handle to attack LSASS, so mask-based detection misses them. Where they run from gives them away: in the test corpus, every legitimate LSASS access came from Windows, Program Files or agent install folders, and every credential tool ran from a Desktop, Downloads, Public or a share.

This rule complements [LSASS Process Opened With Memory Read Access](win_lsass_memory_access.md). Accesses with that rule's read masks are excluded here, so one event never raises both.

## What it detects

Sysmon 10 where:

- `TargetImage` ends with `\lsass.exe`
- `SourceImage` contains `\Users\`, `\AppData\`, `\Temp\`, `\ProgramData\` or `\Downloads\`, **or** starts with `\\` (UNC / network share)
- `GrantedAccess` is **not** one of the memory-read masks (`0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1f0fff`, `0x1f1fff`, `0x1f3fff`, `0x1fffff`)

Not covered:

- **Tools run from `C:\Windows`, Program Files or another "trusted" path,** for example a renamed tool dropped in `System32`. Add a path-based allow-list rule if that's a concern in your environment.
- **Non-system drives** (`D:\`, `Z:\`). Left out on purpose, because servers often run legitimate software from `D:\`. The corpus samples on other drives used read masks and are caught by the memory-read rule.
- **Sources outside the listed folders** that are still user-writable (for example a custom `C:\Tools\` folder).
- **`UNKNOWN` CallTrace frames on their own.** Investigated and rejected: .NET agents and PowerShell produce them during normal operation (8 false positives in the sweep corpus).

## Triage steps

1. **What the source is.** Hash and signer of `SourceImage`, and the folder it ran from. Unsigned binaries on a Desktop, in Downloads, `Users\Public` or a share are the classic pattern.
2. **What mask, and what came next.** `0x1000` alone is query-only. Look for the follow-up: PPLdump-style attacks abuse KnownDlls / `DefineDosDevice` to get code into LSASS, or a protected-process bypass, often with a second process (`services.exe`) touching LSASS right after. Look for dump files (Sysmon 11, `.dmp`) written shortly after.
3. **Process tree.** Pivot on `SourceProcessGUID` to Sysmon 1: who launched the tool, with what command line, and from which session (interactive, RDP or a remote shell).
4. **Driver activity.** For BYOVD-style tools in the same family, check for a driver load (Sysmon 6) or service install (7045) around the same time.
5. **Scope and decide.** Search for the same hash or file name fleet-wide. A documented per-user or portable admin tool can be tuned out by exact path and signer. Anything else should be escalated as credential theft in progress, with LSASS-sourced credentials treated as exposed.

## Known false positives

- **Per-user or portable security, monitoring or backup tools** that query LSASS while running from a user profile or `ProgramData`.
- **Administrators running diagnostic tools** (for example Process Explorer) from their Desktop or Downloads. These usually ask for broader rights, which the memory-read rule would see instead.

Tune by exact `SourceImage` path together with the file signer or hash, never by folder alone.

## Related techniques

- **T1003.001 LSASS Memory:** the technique itself. See also the memory-read rule.
- **T1574.001 DLL:** PPLdump's KnownDlls hijack.
- **T1068 Exploitation for Privilege Escalation:** protected-process (PPL) bypasses and vulnerable-driver tooling.
- **T1036.005 Match Legitimate Resource Name or Location:** tools renamed to blend in, which this rule's path logic still catches if they stay in user folders.
