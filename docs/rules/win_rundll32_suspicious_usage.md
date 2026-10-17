# Rundll32 Running Script, Proxy Export, User-Folder DLL or No Arguments

| | |
|---|---|
| **Rule** | [`rules/windows/stealth/win_rundll32_suspicious_usage.yml`](../../rules/windows/stealth/win_rundll32_suspicious_usage.yml) |
| **Rule ID** | `fac47e33-6ef7-4f7a-8cdc-6e976ee7f717` |
| **Level** | high |
| **ATT&CK** | Stealth: T1218.011 System Binary Proxy Execution: Rundll32 |
| **Log source** | Process creation (Sysmon 1 / Security 4688) |

## Summary

`rundll32.exe` was used as a proxy for something other than calling a normal system DLL export. Attackers use it because it's signed, always present and allowed by most application control. That lets them run script, load their own DLL, dump LSASS with a built-in DLL, or get a clean-looking process to inject into.

## What it detects

`Image` ends with `\rundll32.exe` and `CommandLine` matches any of these branches:

| Branch | Matches | Typical use |
|---|---|---|
| Script | `javascript:`, `vbscript:`, `RunHTMLApplication` | `rundll32 javascript:"\..\mshtml,RunHTMLApplication ";…` running JScript/VBScript or launching `mshta` |
| Proxy export | `comsvcs.dll`, `zipfldr.dll`, `advpack.dll`, `pcwutl.dll`, `ieframe.dll,OpenURL`, `shdocvw.dll,OpenURL` | LSASS `MiniDump`, `RouteTheCall`, `RegisterOCX`/`LaunchINFSection`, `LaunchApplication`, `.url` files that start programs |
| url.dll, not a web link | `url.dll,` without `http://` / `https://` | `FileProtocolHandler` / `OpenURL` with `file://`, a custom protocol (`ms-browser://`) or a bare executable |
| User or data folder | `\Users\Public\`, `\AppData\`, `\Temp\`, `\Downloads\`, `\ProgramData\`, `\PROGRA~3\` | DLL, CPL or a renamed payload (`.jpg`, `.tmp`) loaded from where users and malware can write. The 8.3 form `PROGRA~3` is ProgramData's short path. |
| No arguments | command line ends with `rundll32.exe` or `rundll32.exe"` | Rundll32 started empty as a host for injected code (Meterpreter, Cobalt Strike-style spawn-to, side-loading loaders) |

Not covered:

- **Relative DLLs with no path,** for example `rundll32 AllTheThings.dll,EntryPoint` or `rundll32 .\Outflank-Dumpert-DLL.dll, Dump`. Legitimate calls look the same (`shell32.dll,Control_RunDLL`). Catching them needs an allow-list of system DLLs and exports, or a Sysmon 7 image-load check for unsigned DLLs.
- **Malicious DLLs loaded from clean system paths** (`C:\Windows\System32\…`) with ordinary-looking exports.
- **Renamed `rundll32.exe`.** Matching is on `Image`, as in the other rules, because Sentinel's `SecurityEvent` has no `OriginalFileName` column.
- **Other proxy binaries:** `regsvr32`, `mshta`, `msiexec`, `odbcconf` and so on.

## Triage steps

1. **Identify the branch from the command line.**
   - Script: decode the JavaScript/VBScript and look for URLs or `ActiveXObject` calls.
   - `comsvcs MiniDump`: an LSASS dump. Treat it like rule 1 (LSASS memory access) and look for the `.dmp` file.
   - Proxy export or `url.dll`: identify what was launched (the next child process).
   - User path: collect and hash the DLL/CPL. Check its signer and its real file type; payloads are often renamed `.jpg`, `.tmp` or `.dat`.
   - No arguments: treat as likely injection. Look at Sysmon 8 (CreateRemoteThread) and 10 (process access) targeting this rundll32 PID, its network connections (Sysmon 3), and its parent.
2. **Check the parent.** Office, `mshta`, `wscript`, `WmiPrvSE`, a scheduled task or `services.exe` parents are high-signal. `explorer.exe` with a user-folder CPL often means the user double-clicked a phishing attachment.
3. **Follow the children and network.** Rundll32 starting `cmd`, PowerShell, `mshta` or a browser, or connecting out, confirms proxy execution or C2.
4. **Look for persistence.** Scheduled tasks, Run keys or services that reference the same rundll32 command line. Several of the source samples persist this way.
5. **Scope.** Search for the same DLL hash or path, or the same command line, across hosts.
6. **Decide.** A signed vendor DLL from its own `ProgramData`/`AppData` folder, with a consistent command line across the fleet, can be tuned out. Script, `comsvcs MiniDump`, no-argument rundll32 or unsigned DLLs from user folders should be escalated.

## Known false positives

- **Legitimate software** that ships a DLL or control panel applet under `ProgramData` or `AppData` and loads it with rundll32. This is the most likely tuning need.
- **Admins using `advpack.dll,LaunchINFSection`** to install INF-based drivers or software.
- **Apps opening `file://` links through `url.dll`** (uncommon).

Tune by the exact command line (DLL path and export) together with the parent. Don't exclude `rundll32.exe` itself or a whole folder.

## Related techniques

- **T1003.001 LSASS Memory:** `comsvcs.dll MiniDump`. Rule 1 covers the LSASS access itself.
- **T1218.002 Control Panel:** `.cpl` files run through `shell32.dll,Control_RunDLL`.
- **T1218.005 Mshta:** script branch commands that start `mshta`.
- **T1055 Process Injection:** argument-less rundll32 used as an injection host.
- **T1574.001 DLL:** side-loading and hijacking chains that hand off to rundll32.
