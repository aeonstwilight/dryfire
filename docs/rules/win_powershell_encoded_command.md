# PowerShell Launched With Encoded or Base64-Decoded Command

| | |
|---|---|
| **Rule** | [`rules/windows/execution/win_powershell_encoded_command.yml`](../../rules/windows/execution/win_powershell_encoded_command.yml) |
| **Rule ID** | `d8bb28aa-d181-47ca-8da6-72692aa317de` |
| **Level** | medium |
| **ATT&CK** | Execution: T1059.001 PowerShell; Stealth: T1027.010 Command Obfuscation |
| **Log source** | Process creation (Sysmon 1 / Security 4688) |

## Summary

PowerShell was started with its real command hidden: either passed as Base64 with `-EncodedCommand` (or an abbreviation of it), or decoded inline with `FromBase64String`. This is standard in C2 launchers, loaders and webshells. It's also used by some legitimate management tooling, which is why the level is medium.

## What it detects

Process creation where `Image` ends with `\powershell.exe` or `\pwsh.exe`, and either:

- **Encoded-command flag.** `CommandLine` contains ` -e `, ` -ec `, ` -en `, ` -enc `, ` -enco `, ` -encod `, ` -encode ` or ` -encoded`. Matching also covers `/` and the Unicode dashes (–, —, ―), which PowerShell accepts in place of `-`.
  - The short forms need a trailing space, and only `-encoded` is an open prefix. So `-EncodedCommand` and `-EncodedArguments` match, but `-Encoding` (for example `Get-Content -Encoding UTF8` or `Out-File -Encoding ascii`) does not. The test data includes both cases.
- **Inline decode.** `CommandLine` contains `FromBase64String`. This catches launchers that skip the flag and decode inside `-Command`, such as Meterpreter's `GzipStream` + `FromBase64String` stager.

Not covered:

- **Renamed PowerShell binaries.** Matching is on `Image` only. `OriginalFileName` was left out because Sentinel's `SecurityEvent` table has no equivalent column. Renamed PowerShell is a candidate for its own rule.
- **Other obfuscation styles.** Backtick escapes, `[char]` arrays, string reversal, `-join`/`-replace` tricks and other Invoke-Obfuscation output aren't covered, because the test datasets don't contain them.
- **PowerShell hosted in other processes.** Unmanaged PowerShell, PowerShell via .NET in another binary, and `System.Management.Automation.dll` loaded by non-PowerShell processes. These need image-load or script block (4104) telemetry.
- **Encoded content in a parent process.** For example, a scheduled task or service whose definition holds the encoded string, where `Image` isn't PowerShell.

## Triage steps

1. **Decode the payload.** Take the Base64 after the flag and decode it as UTF-16LE, which is what `-EncodedCommand` uses. For `FromBase64String` launchers, decode the embedded string; if it starts with `H4sI`, it's gzip and needs decompressing. The decoded script decides most cases.
2. **Check the parent.**
   - **High-signal parents:** Office apps, `wscript`/`cscript`/`mshta`/`regsvr32`/`rundll32`, `w3wp.exe` or other web server processes (possible webshell), `WmiPrvSE.exe` (remote WMI execution), `wsmprovhost.exe` (PowerShell remoting), `services.exe` or `svchost.exe` (service or scheduled task).
   - **Expected parents:** an RMM, config-management or deployment agent's own binary.
3. **Check the user and host.** A SYSTEM process on a server under a known agent is different from a user session on a workstation. Look at integrity level and logon session.
4. **Look at what PowerShell did next.** Pivot on its process GUID to network connections (Sysmon 3), child processes, files written (Sysmon 11), and script block logs (4104) for the same time window if they're enabled. They show the decoded script as it ran.
5. **Scope.** Search for the same encoded string, or the same decoded content, on other hosts. Empire and similar launchers reuse the same stager across hosts.
6. **Decide.** A decoded payload that matches a known management tool's behaviour, launched by that tool's binary, can be tuned out (see below). Download cradles (`Net.WebClient`, `DownloadString`, `IEX`), AMSI or logging tampering, reflective loading, or an unknown parent should be escalated.

## Known false positives

- **Management and deployment agents.** Configuration management, RMM, monitoring and software-deployment tools often pass scripts with `-EncodedCommand` to avoid quoting problems.
- **Cloud VM extensions and orchestration.** These may also pass scripts as Base64.
- **Admin one-liners** that decode Base64 inline. Uncommon on the command line, but possible.

When tuning, exclude by the parent's exact path and, if your SIEM has it, its signer. A known parent is necessary but not sufficient: if the decoded content has changed from what that tool normally runs, look at it. Don't exclude by decoded-content keywords alone, because they're easy for an attacker to copy.

## Related techniques

- **T1140 Deobfuscate/Decode Files or Information:** inline `FromBase64String` and gzip decompression in the launcher.
- **T1105 Ingress Tool Transfer:** decoded payloads are often download cradles for the next stage.
- **T1047 Windows Management Instrumentation:** encoded PowerShell under `WmiPrvSE.exe` points to remote WMI execution.
- **T1021.006 Windows Remote Management:** encoded PowerShell under `wsmprovhost.exe` points to PowerShell remoting.
- **T1505.003 Web Shell:** encoded PowerShell under `w3wp.exe` or another web server process.
- **T1059.005 Visual Basic:** VBS and HTA launchers (`wscript`, `mshta`) commonly start the encoded PowerShell stage.
