# WMI Provider Host Spawning a Shell, Proxy Binary or User-Folder Executable

| | |
|---|---|
| **Rule** | [`rules/windows/execution/win_wmiprvse_suspicious_child.yml`](../../rules/windows/execution/win_wmiprvse_suspicious_child.yml) |
| **Rule ID** | `1aeda751-657e-4abe-8879-14df60e40bce` |
| **Level** | high |
| **ATT&CK** | Execution: T1047 Windows Management Instrumentation |
| **Log source** | Process creation (Sysmon 1 / Security 4688) |

## Summary

`WmiPrvSE.exe` started a shell, script host, proxy-execution binary or account/download tool, or an executable from a user, temp or shadow-copy path. Processes created through WMI (`Win32_Process.Create`, `wmic process call create`, `Invoke-CimMethod`) and WMI CommandLineEventConsumers run as children of `WmiPrvSE`. That makes this the host-side footprint of WMI remote execution (Impacket wmiexec, Empire, Covenant) and of WMI event-subscription persistence.

## What it detects

Process creation where `ParentImage` ends with `\wmiprvse.exe` and either:

- **Child binary:** `Image` ends with one of
  - shells and script hosts: `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`
  - proxy-execution binaries: `rundll32.exe`, `regsvr32.exe`, `msbuild.exe`
  - account and download tools: `net.exe`, `net1.exe`, `certutil.exe`, `bitsadmin.exe`
- **Child path:** `Image` contains `\Users\`, `\AppData\`, `\Temp\` or `HarddiskVolumeShadowCopy`. That covers anything run from a user or temp folder, or straight out of a volume shadow copy.

Not covered:

- **Custom implants at clean system paths,** for example Covenant's `GruntHTTP2.exe` in `C:\Windows\System32` launched via WMI. This rule lists suspicious children rather than flagging every child of `WmiPrvSE`. A "rare child of WmiPrvSE" rule with an allow-list would catch these, at the cost of more tuning.
- **ActiveScriptEventConsumer** subscriptions. Their scripts run inside `scrcons.exe`, not as `WmiPrvSE` children.
- **The WMI activity that sets things up:** remote WMI connections, subscription creation (Sysmon 19/20/21, WMI-Activity/Operational 5861). This rule sees only the resulting process.

## Triage steps

1. **Local or remote?** Check the child's `User` and the logon session. Pivot to Security 4624 type 3 on this host just before, and its source IP. Remote WMI from an unexpected source is the main lead.
2. **Read the command line.**
   - Impacket wmiexec has a fingerprint: `cmd.exe /Q /c <command> 1> \\127.0.0.1\ADMIN$\__<timestamp> 2>&1`. Collect the commands run, because they show the attacker's actions.
   - Encoded PowerShell: decode it.
   - `net user /add`, `net localgroup administrators … /add`: account backdoors.
   - `MSBuild` with an `.xml` or `.csproj` project from `Windows\Tasks` or `Temp`: inline-task code execution.
3. **Check for a persistent subscription.** Run as SYSTEM with no matching inbound logon may mean an event subscription. Check Sysmon 19, 20 and 21, WMI-Activity/Operational 5861, and the `root\subscription` namespace (`__EventFilter`, `CommandLineEventConsumer`, `__FilterToConsumerBinding`).
4. **Look at the output and artefacts.** Check for wmiexec output files under `ADMIN$`/`C$`, binaries dropped in `ProgramData` or `Temp`, and executables referenced from shadow-copy paths. The last one means the attacker is hiding a payload in a VSS snapshot.
5. **Scope.** Search the source host for outbound WMI (`wmic /node:`, Impacket, PowerShell `-ComputerName`) and for the same child command lines on other targets.
6. **Decide.** A documented management tool or admin using WMI process creation from a known management host can be tuned out. Remote shells, account creation, encoded PowerShell, proxy binaries or shadow-copy executables should be escalated as lateral movement or persistence.

## Known false positives

- **Admins and management platforms** creating processes remotely with WMI (`Win32_Process.Create`, `wmic process call create`, `Invoke-CimMethod`).
- **Monitoring and inventory agents** that run `cmd` or PowerShell through WMI.

Tune by the source of the WMI connection (management host or service account) together with the exact child command line. Don't exclude a child binary outright: `cmd.exe` under `WmiPrvSE` is exactly what Impacket produces.

## Related techniques

- **T1546.003 WMI Event Subscription:** CommandLineEventConsumers whose commands appear as `WmiPrvSE` children.
- **T1021.002 SMB/Windows Admin Shares:** wmiexec and similar tools read their output back over `ADMIN$`/`C$`.
- **T1127.001 MSBuild:** inline-task execution launched through WMI.
- **T1136.001 Local Account:** backdoor accounts created with `net user /add`.
- **T1218.011 Rundll32:** DLL payloads started via WMI.
- **T1006 Direct Volume Access:** payloads executed from volume shadow copy paths.
- **T1059.001 PowerShell:** encoded PowerShell stagers launched via WMI.
