# Office Application Spawning a Shell or Script Host

| | |
|---|---|
| **Rule** | [`rules/windows/execution/win_office_spawning_shell_or_script_host.yml`](../../rules/windows/execution/win_office_spawning_shell_or_script_host.yml) |
| **Rule ID** | `b2a87c57-2fa0-4a0d-970c-f0e5e721676c` |
| **Level** | high |
| **ATT&CK** | Execution: T1204.002 Malicious File, T1059.001 PowerShell, T1059.003 Windows Command Shell |
| **Log source** | Process creation (Sysmon 1 / Security 4688) |

## Summary

An Office application started a command shell, PowerShell or a script host. Office has almost no reason to do that. It's the classic sign of a malicious macro, embedded object, DDE field or document exploit handing off to the next stage, or of an Office binary being abused to load a malicious DLL.

## What it detects

Process creation where:

- **Parent** (`ParentImage`) ends with `\winword.exe`, `\excel.exe`, `\powerpnt.exe`, `\outlook.exe`, `\msaccess.exe`, `\mspub.exe`, `\onenote.exe` or `\eqnedt32.exe` (legacy Equation Editor, CVE-2017-11882 family).
- **Child** (`Image`) ends with `\cmd.exe`, `\powershell.exe`, `\pwsh.exe`, `\wscript.exe`, `\cscript.exe` or `\mshta.exe`.

The parent is matched by file name only, not install path. That's deliberate: the real positive sample is a genuine `WINWORD.exe` copied to `AppData\Roaming` for `wwlib.dll` side-loading, and a path check would have missed it.

Not covered:

- **`rundll32` and `regsvr32` children.** Office starts `rundll32` legitimately (printing, control panel applets). These belong to the suspicious rundll32 rule.
- **Payloads that never start a child process.** VBA that injects shellcode, calls APIs directly, uses WMI (`Win32_Process.Create` makes the child a `WmiPrvSE.exe` child; see the WMI rule) or drops a file for later execution.
- **Office started over DCOM** (`/automation -Embedding`) running Excel 4.0 macros that don't spawn a shell, as in the OTRF Covenant dataset.
- **Other Office-adjacent hosts:** Visio, Project, Teams, and third-party PDF or Office suites.

## Triage steps

1. **Identify the document.** Check the parent's command line for the opened file path. Look at Sysmon 11 and 15 (Zone.Identifier) for where the document came from, and the email (Outlook cache, `Content.Outlook`) or browser download behind it.
2. **Read the child's command line.** Look for encoded PowerShell (decode it; see the encoded PowerShell triage note), `mshta` with a URL, `cmd /c` running a script from `Temp` or `Public`, or download cradles.
3. **Check the parent itself.** Is the Office binary running from its normal install path (`Program Files\Microsoft Office\…`)? If not (AppData, Temp, Downloads), it's a side-loading setup: look for an unexpected DLL next to it (`wwlib.dll` for Word) and how both got there.
4. **Follow the chain.** Look at network connections from the child (Sysmon 3), files it wrote, and further processes. Look for persistence created shortly after: Run keys, scheduled tasks (see the scheduled task rule), services.
5. **Scope.** Search for the same document name or hash, the same sender, and the same child command line across hosts. Phishing waves hit many users at once.
6. **Decide.** A known business macro or add-in, with a stable and documented command line, can be tuned out. An unknown document, an encoded or downloading child, or an Office binary outside its install path should be escalated.

## Known false positives

- **Business macros, Excel add-ins and Access databases** that run `cmd` or PowerShell as part of a workflow, such as finance or reporting automation.
- **Document management or reporting tools** that run scripts from inside Office.

Tune by the exact parent path together with the exact child command line, ideally per document or add-in. Don't exclude a whole parent: that removes coverage for every phishing document opened in that application.

## Related techniques

- **T1566.001 Spearphishing Attachment:** the usual delivery for the documents behind this activity.
- **T1203 Exploitation for Client Execution:** Equation Editor and other document exploits.
- **T1559.002 Dynamic Data Exchange:** DDE fields that start `cmd` without a macro.
- **T1574.001 DLL:** DLL side-loading through a copied Office binary. ATT&CK v20 merged the old T1574.002 into this.
- **T1218.005 Mshta:** HTA payloads launched from documents.
- **T1059.005 Visual Basic:** the VBA macro that does the launching.
- **T1137 Office Application Startup:** Office-based persistence (templates, add-ins) that may follow.
