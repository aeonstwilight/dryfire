# Windows Security Event Log Cleared

| | |
|---|---|
| **Rule** | [`rules/windows/defense_impairment/win_security_log_cleared.yml`](../../rules/windows/defense_impairment/win_security_log_cleared.yml) |
| **Rule ID** | `968031ca-04ab-489f-84e4-7475344ef73b` |
| **Level** | high |
| **ATT&CK** | Defense Impairment: T1685.005 Clear Windows Event Logs |
| **Log source** | Security 1102 (provider Microsoft-Windows-Eventlog) |

## Summary

The Security event log was cleared. Only an explicit clear produces 1102. Size-based rotation, overwrite and auto-archive don't, so every hit means someone, or something, deliberately wiped the log.

## What it detects

Security 1102, from any source:

- `wevtutil cl Security`
- `Clear-EventLog` or `Remove-EventLog`
- Event Viewer → Clear Log
- `EvtClearLog` over the EventLog RPC interface, locally or remotely

The rule has no exclusions.

Not covered:

- **Clearing any other log.** System, Sysmon/Operational, PowerShell/Operational and so on log System 104, not 1102. That's planned as a separate rule after M1, filtered to provider `Microsoft-Windows-Eventlog`, because RdpCoreTS/Operational reuses Event ID 104 for something unrelated.
- **Tampering without a clear.** Stopping or disabling the EventLog service, changing audit policy (4719), shrinking the log size, or patching the EventLog service in memory. These are T1685.001.
- **Clears that never reach the SIEM.** For example, the forwarder was stopped first, or the event was dropped. A host that goes quiet without a 1102 needs a separate "missing logs" check.

## Triage steps

1. **Who cleared it.** Check `SubjectUserName`, `SubjectDomainName` and `SubjectLogonId` in the event. Pivot on the logon ID to the 4624: a network logon (type 3) means the clear came from another host. Look for 5145 on `\PIPE\eventlog` in the same window.
2. **What else was cleared.** Look for System 104 events at the same time. Attackers usually clear several logs in one go. Also check whether Sysmon and PowerShell logs on the host go silent.
3. **How it was done.** Look at process creation just before the clear: `wevtutil.exe cl`, `powershell` with `Clear-EventLog`, `mmc.exe eventvwr.msc`, or nothing at all (remote RPC).
4. **What was hidden.** The Security log is gone locally, but anything forwarded before the clear is still in the SIEM. Pull the host's events from the hour before, plus EDR telemetry and other hosts' logs that reference this one (logons from it, shares accessed on it).
5. **Scope.** Search for 1102 on other hosts around the same time and by the same account. Attackers often clear logs on every host they touched.
6. **Decide.** A planned clear by a known admin, on a documented ticket, during imaging or lab resets, can be closed. Anything else, especially by a service account, over the network or alongside other suspicious activity, should be escalated as anti-forensics.

## Known false positives

- **Admins clearing the log** while troubleshooting, or before capturing a golden image or template VM.
- **Lab, test and training environments** that reset logs between runs. The public datasets this rule is tested on are full of these: about 25 EVTX-ATTACK-SAMPLES files and 5 OTRF datasets contain a 1102 from the author resetting the log before recording.

Don't tune these out in the rule. Handle them in triage or with an allow-list of documented maintenance windows and accounts. One unexpected clear matters more than a few extra tickets.

## Related techniques

- **T1685.001 Disable or Modify Windows Event Log:** stopping or reconfiguring logging instead of clearing it.
- **T1070 Indicator Removal:** the wider family of clean-up activity: file deletion (T1070.004), timestomping and similar.
- **T1021.002 SMB/Windows Admin Shares:** remote clears go over SMB named pipes (`\PIPE\eventlog`).
- **T1059.001 PowerShell:** `Clear-EventLog` and `wevtutil` wrapped in PowerShell are common.
