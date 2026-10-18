# Renamed Shell, Script Host or LOLBin Executed

| | |
|---|---|
| **Rule** | [`rules/windows/stealth/win_renamed_shell_or_lolbin.yml`](../../rules/windows/stealth/win_renamed_shell_or_lolbin.yml) |
| **Rule ID** | `162a5bc1-60f8-4335-a9cd-9ff02fc9c52e` |
| **Level** | high |
| **ATT&CK** | Stealth: T1036.003 Rename Legitimate Utilities |
| **Log source** | Process creation with `OriginalFileName` (Sysmon 1; Defender `ProcessVersionInfoOriginalFileName`) |

## Summary

A Windows shell, script host or proxy binary ran under a different file name. The PE version resource (`OriginalFileName`) says it's, for example, `PowerShell.EXE`, but the file on disk is `svc.exe`. Renaming is a cheap way to slip past name-based detections, including several rules in this repo. The real-world samples are `cmd.exe` copied to `program.exe` for an unquoted-service-path privilege escalation, and to `i.exe` inside a zip in Temp.

## What it detects

Process creation where `OriginalFileName` is one of the binaries below and `Image` does **not** end with that binary's normal name:

| OriginalFileName | Expected name | Seen in test corpus |
|---|---|---|
| `Cmd.Exe` | `cmd.exe` | yes |
| `PowerShell.EXE` | `powershell.exe` | yes |
| `pwsh.dll` | `pwsh.exe` | **no** (synthetic tests only) |
| `CertUtil.exe` | `certutil.exe` | yes |
| `RUNDLL32.EXE` | `rundll32.exe` | yes |
| `REGSVR32.EXE` | `regsvr32.exe` | yes |
| `MSHTA.EXE` | `mshta.exe` | yes |
| `wscript.exe` / `cscript.exe` | same | yes |
| `MSBuild.exe` | `msbuild.exe` | yes |
| `net.exe` / `net1.exe` | same | yes |
| `bitsadmin.exe` | `bitsadmin.exe` | **no** (synthetic tests only) |

These are exactly the binaries that the encoded-PowerShell, certutil, Office-child, WMI-child and rundll32 rules match by file name. This rule covers the renamed case for all of them.

The list is deliberately targeted. In the test corpus, about 35 of 43 `OriginalFileName` mismatches are normal: Google Update, the Azure agent, Teams, Sysinternals 64-bit builds (`PsExec64`, `sdelete64`) and several Windows binaries with different internal names. A generic "any mismatch" rule would be mostly noise.

**Sentinel:** declared unsupported in `pipelines/unsupported_targets.yml`. Security 4688 doesn't record the PE original file name, so there's nothing to match on.

Not covered:

- **Binaries outside the list,** such as renamed hacking tools (`mimikatz.exe` → `m.exe`) or other LOLBins. Those fit better in a hacktool-name or LOLBin-specific rule.
- **Copies with a stripped or edited version resource,** where `OriginalFileName` is blank or changed.
- **Telemetry without `OriginalFileName`:** Security 4688, and older Sysmon versions.

## Triage steps

1. **Where the copy lives.** A renamed system binary in `Users\Public`, `Temp`, `ProgramData`, a web root, or an odd path like `C:\Program Files\vulnsvc\program.exe` (an unquoted service path) is a strong signal.
2. **How it got there.** Look for the file creation (Sysmon 11) or a `copy`/`Copy-Item` command shortly before, and which process wrote it.
3. **What it ran.** Read the command line as if it were the real binary, and apply the matching rule's triage note: encoded PowerShell, a certutil download, rundll32 proxy use and so on.
4. **Parent and user.** A service (`services.exe`) launching it points to unquoted-path or service-hijack privilege escalation. Office or a script host points to an initial-access chain.
5. **Scope.** Search for the same hash or renamed path on other hosts.
6. **Decide.** A documented packaging or installer tool shipping a renamed copy can be tuned out by exact path and hash. Anything else should be escalated.

## Known false positives

- **Software bundling a renamed copy** of a Windows shell or script host. This is rare, usually an installer or packaging tool.

Tune by exact `Image` path together with the file hash. Never exclude by `OriginalFileName`, because that's what the attacker's copy carries too.

## Related techniques

- **T1574.009 Path Interception by Unquoted Path:** the `program.exe` sample is a renamed `cmd.exe` planted for an unquoted service path.
- **T1059.001 PowerShell / T1059.003 Windows Command Shell:** the renamed interpreters themselves.
- **T1218 System Binary Proxy Execution:** renamed `rundll32`, `regsvr32`, `mshta` and `msbuild`.
- **T1105 Ingress Tool Transfer:** renamed `certutil` and `bitsadmin` used as downloaders.
