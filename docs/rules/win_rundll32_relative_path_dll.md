# Rundll32 Loading a DLL by Bare Name Not on the Allow-List

| | |
|---|---|
| **Rule** | [`rules/windows/stealth/win_rundll32_relative_path_dll.yml`](../../rules/windows/stealth/win_rundll32_relative_path_dll.yml) |
| **Rule ID** | `853446b7-6671-455a-8c2d-d106a015e256` |
| **Level** | medium |
| **ATT&CK** | Stealth: T1218.011 System Binary Proxy Execution: Rundll32 |
| **Log source** | Process creation (Sysmon 1 / Security 4688) |

## Summary

`rundll32.exe` was given a DLL by file name only, with no folder, and the name isn't one of the Windows DLLs normally called that way. A bare name is resolved through the DLL search order (the rundll32 folder, System32, the current folder and `PATH`). Attackers rely on this to run a payload from the folder they're working in, to load a DLL they planted in System32 under a name Windows doesn't ship, or to hide behind an 8.3 short name. Normal use of a bare name is almost always a known Windows DLL, so an allow-list keeps this quiet.

## What it detects

Process creation where `Image` ends with `\rundll32.exe` and the first argument after `rundll32[.exe]`:

- has no `\`, `/` or `:` in it (no folder, no drive, no URL or `javascript:`), and
- isn't one of the allow-listed DLLs, with or without `.dll`: `shell32`, `user32`, `url`, `ieframe`, `shdocvw`, `zipfldr`, `pcwutl`, `advpack`, `printui`, `keymgr`, `setupapi`, `powrprof`, `appxdeploymentextensions.onecore`.

The entry point can follow a comma (`evil.dll,Start`, `evil.dll,#1`) or a space (`conf3234.dll f8753`). The match is case-insensitive and handles a quoted image or DLL name. Any extension counts (`.dat`, `.lock`, none at all).

The proxy DLLs on the allow-list (`url`, `zipfldr`, `advpack`, `pcwutl`, `ieframe`, `shdocvw`) are allowed here because [Rundll32 Running Script, Proxy Export, User-Folder DLL or No Arguments](win_rundll32_suspicious_usage.md) already alerts on their dangerous exports, so one event doesn't raise two alerts.

Not covered:

- **Relative paths with a folder part** (`.\evil.dll`, `..\x.dll`, `sub\x.dll`). The backslash makes them look like a path. Candidate for a follow-up branch.
- **A planted DLL with an allow-listed name** placed earlier in the search order, for example `shell32.dll` dropped in the current folder. Rundll32 checks its own folder (System32) first, so this only works for names missing from System32.
- **Full or UNC paths:** covered by the suspicious-usage rule when they're in a user or data folder, otherwise not covered.
- **Renamed rundll32:** see the renamed-binary rule.

## Triage steps

1. **What was loaded.** Note the DLL name and entry point (export name, ordinal `#n`, or space-separated arguments). Random-looking names, ordinals and non-DLL extensions stand out.
2. **Which file was actually loaded.** Bare names are resolved at run time. Check the Sysmon 7 (ImageLoad) event from the rundll32 process for the full path, then its hash and signer. If it's in System32, check whether Windows ships that name; a missing-DLL name that only exists on this host points to a planted DLL (search-order hijack).
3. **Current folder and parent.** Look at the parent command line and `CurrentDirectory`: a user, temp or download folder means the DLL was probably dropped there. A service parent (`svchost.exe`) starting rundll32 with an unknown DLL points to a hijacked service.
4. **Where the DLL came from.** Sysmon 11 (FileCreate) of the DLL shortly before, and the process that wrote it: a browser, an archive tool, Office, or a decode step (see the certutil encode/decode rule).
5. **What it did.** Network connections (Sysmon 3), child processes, and persistence (scheduled tasks, Run keys, services) referencing the same DLL.
6. **Decide.** A signed vendor or Windows DLL can be added to the allow-list (see below). An unsigned DLL from a user-writable folder, or a planted System32 DLL, should be escalated.

## Known false positives

- **Windows or vendor DLLs called by bare name that aren't on the list yet,** for example control panel or setup helpers in a specific environment.
- **Installers** that change into their own folder and call rundll32 on a bundled DLL.

Tune by adding the DLL name to the allow-list only after checking the loaded path and signer (step 2). Don't add short or generic names that an attacker could reuse.

## Related techniques

- **T1218.011 Rundll32:** the technique itself. See also the suspicious-usage rule.
- **T1574.001 DLL:** DLL search-order hijacking and planted DLLs in System32, as in the Update Session Orchestrator sample.
- **T1036.005 Match Legitimate Resource Name or Location:** DLL names made to look like Windows files.
- **T1140 Deobfuscate/Decode Files or Information:** payload DLLs decoded on the host before being run.
