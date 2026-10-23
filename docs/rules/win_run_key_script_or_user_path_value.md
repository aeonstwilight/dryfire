# Run Key Value Pointing to a Script Host, LOLBin or User-Writable Path

| | |
|---|---|
| **Rule** | [`rules/windows/persistence/win_run_key_script_or_user_path_value.yml`](../../rules/windows/persistence/win_run_key_script_or_user_path_value.yml) |
| **Rule ID** | `77418687-8816-4a7f-924f-970be0beaf0f` |
| **Level** | medium |
| **ATT&CK** | Persistence, Privilege Escalation: T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| **Log source** | Sysmon event 13 (registry value set) |

## Summary

A Run or RunOnce value was set to a command that starts a script host or LOLBin, or a program in a user-writable folder. Legitimate autostart entries usually point to an installed program under Program Files or system32. Malware and post-exploitation frameworks (Empire, APT29's toolkit, commodity loaders) prefer PowerShell one-liners, rundll32 with a dropped DLL, or an executable in AppData, Public or ProgramData, because these need no installer and no admin rights in HKCU.

## What it detects

Sysmon event 13 where `TargetObject` contains `\CurrentVersion\Run` (Run, RunOnce, RunOnceEx, RunServices, in HKLM, HKCU/HKU and WOW6432Node) or `\Policies\Explorer\Run`, and `Details` (the value data) contains one of:

- **Script hosts and LOLBins:** `powershell`, `pwsh`, `cmd.exe`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`
- **User-writable folders:** `\AppData\Roaming\`, `\Temp\`, `\Users\Public\`, `\ProgramData\`, `\Windows\Tasks\`, `\PerfLogs\`

Not covered:

- **`AppData\Local`** (outside `Temp`), left out on purpose: most per-user installers (Teams, OneDrive, Slack, Discord) put their autostart program there. A payload dropped in `AppData\Local` and started directly is missed.
- **Payloads in other folders**, such as a renamed binary under Program Files, or Atomic Red Team's `C:\Path\` placeholder values in the Panache sample.
- **Other autostart locations:** Winlogon `Userinit`/`Shell`, `Active Setup`, services, scheduled tasks (the scheduled-task and service rules), and the Startup folder.
- **Writes that don't produce Sysmon 13**, for example offline hive edits, or a Sysmon config that doesn't log Run keys.
- **Sentinel:** declared unsupported. `SecurityEvent` has no column for the value data.

Defender (`DeviceRegistryEvents`) and Elastic (`registry.path`, `registry.data.strings`) convert. Defender records the key and the value name separately, so the key match is written to work on the key alone.

## Triage steps

1. **What does the value run?** Read `Details` in full. Decode any encoded PowerShell, and note the DLL and export for rundll32/regsvr32 and the file path for anything in a user folder.
2. **Who wrote it?** Check `Image` and `User`. A script host, Office application, `reg.exe` run from a shell, `wmiprvse.exe` (WMI's registry provider) or `svchost.exe` writing remotely (Remote Registry) is suspicious. So is a freshly dropped binary. An installer (`msiexec.exe`, a signed setup program) is more often benign.
3. **Is the target file legitimate?** Check that it exists, its hash, its signature and when it was created (Sysmon 11 for the file write). Look for timestomping: a creation time older than its first appearance.
4. **What else happened on the host around then?** The process tree that led to the write (Sysmon 1), network connections from the writer, and other persistence: scheduled tasks, services, WMI subscriptions. For Remote Registry or WMI writes, find the source host from the logon events.
5. **Decide.** A known product's updater or helper, signed and installed through the normal route, is benign: tune it out locally by value name and data. Otherwise delete the value, remove the payload and investigate how it got there.

## Known false positives

- **Software that starts a helper** through rundll32, PowerShell or a script at logon.
- **Per-user applications** in `AppData\Roaming` or `ProgramData` (some updaters, chat clients and games).
- **Installers** that use RunOnce to finish setup from a Temp folder after a reboot.

## Related techniques

- **T1112 Modify Registry:** the write itself.
- **T1059.001 PowerShell** and **T1218.011 Rundll32:** what the value usually runs (the encoded-PowerShell and rundll32 rules).
- **T1546.003 WMI Event Subscription** and **T1053.005 Scheduled Task:** other persistence often set up alongside (the WMI and scheduled-task rules).
- **T1021 Remote Services:** Run values written over Remote Registry or WMI from another host.
