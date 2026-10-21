# WMI Event Subscription Bound to a Command Line or Script Consumer

| | |
|---|---|
| **Rule** | [`rules/windows/persistence/win_wmi_event_subscription_code_consumer.yml`](../../rules/windows/persistence/win_wmi_event_subscription_code_consumer.yml) |
| **Rule ID** | `10c9b53b-a93a-4c6d-8c7c-aa8dd7801719` |
| **Level** | high |
| **ATT&CK** | Persistence, Privilege Escalation: T1546.003 Windows Management Instrumentation Event Subscription |
| **Log source** | Sysmon 21 (WmiEvent, filter-to-consumer binding) |

## Summary

A permanent WMI event subscription went live with a consumer that runs code. From now on WMI (`WmiPrvSE.exe`, or `scrcons.exe` for scripts) runs the command or script as SYSTEM whenever the filter's event fires: a timer, a logon, an uptime threshold. It's fileless persistence that survives reboots and isn't visible in the usual autostart locations. APT29 used exactly this in the day 2 evaluation (`WindowsParentalControlMigration` running encoded PowerShell on logon).

## What it detects

Sysmon 21 where `Operation` is `Created` or `Modified` and `Consumer` contains `CommandLineEventConsumer` or `ActiveScriptEventConsumer`.

- The binding (21) is the event that makes the subscription active, so each install gives one alert. It's also the only event that caught OTRF's Covenant run, whose consumer event (20) has no parsed fields.
- The binding doesn't show the command or script; the consumer event (20) with the same name does (`Destination`, `Type`). See triage step 1.
- `NTEventLogEventConsumer`, `LogFileEventConsumer` and `SMTPEventConsumer` can't run code and are not matched (including Windows' default "SCM Event Log Consumer").

Not covered:

- **No Sysmon 19–21** (WmiEvent not configured) or a subscription created while Sysmon wasn't running. WMI-Activity/Operational 5861 records permanent subscriptions too and is the fallback.
- **Custom or third-party consumer classes** that run code.
- **Temporary (in-process) subscriptions,** which end with the process and aren't persistence.
- **Sentinel and Defender:** no query. Sysmon WMI events have no table in either backend ("unsupported", like the other Sysmon rules outside process creation).

## Triage steps

1. **Read the consumer.** Find the Sysmon 20 on the same host with the consumer name from `Consumer`: `Destination` holds the command line or script. Encoded PowerShell, download cradles, LOLBins, scripts fetching URLs, or binaries in user-writable paths are malicious until shown otherwise.
2. **Read the filter.** Find the Sysmon 19 named in `Filter`: the WQL query says when it fires. `Win32_PerfFormattedData_PerfOS_System` with an uptime condition, `Win32_LogonSession`/`Win32_LoggedOnUser` creation, or a short `__TimerEvent` are common persistence triggers.
3. **Who created it, and how.** `User` on the 19/20/21 events, and the process that made the WMI calls around that time: `wmic /namespace:\\root\subscription`, PowerShell `Set-WmiInstance`/`Register-WmiEvent`, a script host, or a remote WMI connection (4624 type 3 followed by `WmiPrvSE.exe` activity) for remote installs like Covenant's.
4. **Has it fired?** Look for child processes of `WmiPrvSE.exe` or `scrcons.exe` matching the consumer's command (the WMI provider host rule), and their network connections.
5. **Scope.** Search other hosts for the same consumer or filter name (names like `Updater`, `WSUS_*`, `SCM Event Consumer` look-alikes are reused across a deployment).
6. **Decide and clean up.** For a malicious subscription, remove the binding, consumer and filter from `root\subscription` (and check `root\default` and other namespaces), then handle the payload it ran. Tune known vendor agents by exact consumer name plus command.

## Known false positives

- **Management, monitoring or vendor agents** that register their own command-line or script consumers. Check the consumer name and command against the product.
- **Administrators** using WMI subscriptions for scheduled maintenance (rare; scheduled tasks are the normal choice).

## Related techniques

- **T1047 Windows Management Instrumentation:** creating the subscription, and the processes it later starts under `WmiPrvSE.exe` (the WMI provider host rule).
- **T1059.001 PowerShell:** the usual consumer payload, often encoded (the encoded-PowerShell rule).
- **T1053.005 Scheduled Task:** the more common persistence alternative (the scheduled-task rule).
- **T1021.006 / T1021.003:** remote WMI or DCOM used to install subscriptions on other hosts.
