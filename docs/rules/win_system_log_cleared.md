# Windows Event Log Other Than Security Cleared

| | |
|---|---|
| **Rule** | [`rules/windows/defense_impairment/win_system_log_cleared.yml`](../../rules/windows/defense_impairment/win_system_log_cleared.yml) |
| **Rule ID** | `182e1296-8856-49de-ac0a-00ad45bb8676` |
| **Level** | high |
| **ATT&CK** | Defense Impairment: T1685.005 Clear Windows Event Logs |
| **Log source** | System 104 (provider Microsoft-Windows-Eventlog) |

## Summary

An event log other than Security was cleared: System, Application, Sysmon/Operational, PowerShell/Operational, or any other channel. Windows logs this as System 104. It's the counterpart of the Security 1102 rule. Attackers clear these logs to remove Sysmon, PowerShell and service-install evidence, often in the same burst as the Security log.

## What it detects

System 104 on the System channel. The event's `Channel` field (`UserData/LogFileCleared/Channel`) names the log that was cleared. Depending on your collector, that may appear as a separate field from the System channel the event itself sits in.

Other channels reuse Event ID 104 for unrelated events, for example RdpCoreTS/Operational. They don't match because the rule is scoped to the System channel. The negative test includes 21 such RdpCoreTS events.

There's deliberately no provider filter. Collectors name the provider field differently (`Provider_Name`, `SourceName`), and in the test corpus every System-channel 104 comes from `Microsoft-Windows-Eventlog`.

Not covered:

- **Security log clears** (Security 1102). See the Security log rule.
- **Tampering without a clear:** disabling a channel (`wevtutil sl … /e:false`), stopping the EventLog service, or changing a channel's retention or size. These are T1685.001.
- **Clears that never reach the SIEM,** for example when forwarding is stopped first.

## Triage steps

1. **Which log was cleared.** Read the cleared channel name from the event. Sysmon/Operational, PowerShell/Operational, Windows PowerShell, TaskScheduler/Operational or System itself are the most significant, because they hold the evidence for execution, persistence and lateral movement.
2. **Who cleared it.** Check `SubjectUserName` and `SubjectDomainName` in the event, then pivot to the 4624 for that account on this host around the same time.
3. **The rest of the burst.** Look for a Security 1102 and further 104s within seconds. Clearing several logs at once (`wevtutil el | foreach wevtutil cl`, `Clear-EventLog`, a C2 module) is the typical anti-forensics pattern.
4. **How.** Look at process creation just before: `wevtutil.exe cl <channel>`, PowerShell `Clear-EventLog` / `Remove-EventLog` / `[System.Diagnostics.Eventing.Reader.EventLogSession]`, or Event Viewer.
5. **What was hidden.** Pull everything already forwarded from this host for the preceding period. Sysmon and PowerShell data in the SIEM survives a local clear.
6. **Decide.** A planned clear by a known admin (imaging, lab reset) can be closed with a ticket. A clear of Sysmon or PowerShell logs by anyone else, or alongside other suspicious activity, should be escalated as anti-forensics.

## Known false positives

- **Admins clearing logs** while troubleshooting, or before capturing a golden image or template VM.
- **Lab, test and training environments** that reset logs between runs. As with 1102, several public datasets contain 104s from the author's own reset before recording.

Handle these in triage or with an allow-list of documented maintenance windows and accounts, rather than in the rule.

## Related techniques

- **T1685.001 Disable or Modify Windows Event Log:** disabling channels or the EventLog service instead of clearing.
- **T1070 Indicator Removal:** the wider clean-up family (file deletion, timestomping).
- **T1059.001 PowerShell:** `Clear-EventLog` and `wevtutil` run from PowerShell.
