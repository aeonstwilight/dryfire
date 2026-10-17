# Member Added to a Privileged Built-in Group Other Than Administrators

| | |
|---|---|
| **Rule** | [`rules/windows/persistence/win_privileged_builtin_group_member_added.yml`](../../rules/windows/persistence/win_privileged_builtin_group_member_added.yml) |
| **Rule ID** | `fca64eca-1a82-404f-879a-097c3fbdac4a` |
| **Level** | medium |
| **ATT&CK** | Persistence, Privilege Escalation: T1098.007 Account Manipulation: Additional Local or Domain Groups |
| **Log source** | Security 4732 (requires "Audit Security Group Management") |

## Summary

An account was added to a built-in group that gives remote access or strong rights without full local admin. Attackers use these groups for quieter persistence (RDP or WinRM access), for privilege escalation (Backup Operators can read any file, including SAM, SYSTEM and NTDS.dit), and on domain controllers for near-domain-admin control (Account, Server and Print Operators). Administrators itself is covered by [Member Added to Local Administrators Group](win_local_admin_group_member_added.md).

## What it detects

Security 4732 where `TargetSid` is one of these groups. Matching is on the SID, so localized or renamed groups match too.

| Group | SID | Why it matters | Priority |
|---|---|---|---|
| Backup Operators | `S-1-5-32-551` | `SeBackupPrivilege`/`SeRestorePrivilege`: read or overwrite any file, dump SAM/SYSTEM, copy NTDS.dit on DCs | **high** |
| Account Operators | `S-1-5-32-548` | DC only: create and modify most users and groups | **high** |
| Server Operators | `S-1-5-32-549` | DC only: log on to DCs, change services, back up/restore | **high** |
| Print Operators | `S-1-5-32-550` | DC only: load printer drivers (code execution on DCs) | **high** |
| Hyper-V Administrators | `S-1-5-32-578` | full control of VMs, including virtual DCs | medium |
| Remote Management Users | `S-1-5-32-580` | WinRM / PowerShell remoting access | medium |
| Distributed COM Users | `S-1-5-32-562` | remote DCOM activation (lateral movement) | medium |
| Remote Desktop Users | `S-1-5-32-555` | RDP logon | lower: often routine |

Not covered:

- **Administrators:** see the Administrators rule.
- **Domain groups** (Domain Admins, Enterprise Admins, DnsAdmins and others, logged as 4728/4756 or with domain-specific SIDs). Candidate follow-up rule.
- **Lower-impact built-ins,** such as Event Log Readers or Network Configuration Operators, left out on purpose.
- **Changes made without a 4732** (GPO Restricted Groups with auditing off, offline edits).

## Triage steps

1. **Which group.** Use the table above. Backup, Account, Server and Print Operators get immediate attention, especially on domain controllers.
2. **Who was added (`MemberSid`, and `MemberName` for domain accounts).** Look for newly created accounts (4720 shortly before), service accounts, disabled or dormant accounts that were recently re-enabled (4722), and built-in principals.
3. **Who made the change (`SubjectUserName`, `SubjectLogonId`).** Pivot to the 4624 and the process that made it: `net localgroup`, `Add-LocalGroupMember`, `net.exe` under `WmiPrvSE`, or a remote MMC/ADSI session.
4. **Is it policy?** Compare against GPO Restricted Groups, Intune or helpdesk tickets. Many RDP and WinRM grants are legitimate.
5. **What happened next.** Logons by the new member (4624 type 10 for RDP, WinRM/PowerShell remoting sessions). For Backup Operators: `reg save HKLM\SAM`/`SYSTEM`, `wbadmin`, `robocopy /b`, or `diskshadow` on DCs.
6. **Decide.** Ticketed RDP or WinRM grants can be closed. Unexpected adds to the high-priority groups, or adds of new or dormant accounts, should be escalated.

## Known false positives

- **Helpdesk granting RDP or WinRM access** to users or support staff.
- **GPO Restricted Groups or Intune policies** re-applying membership.
- **Backup software installers** adding their service account to Backup Operators.

Tune by group plus subject plus member together, for example "the helpdesk group adding to Remote Desktop Users on workstations". Don't tune out the high-priority groups by subject alone.

## Related techniques

- **T1098 Account Manipulation:** the parent technique.
- **T1136.001 Local Account / T1136.002 Domain Account:** new accounts created just before being added.
- **T1021.001 Remote Desktop Protocol / T1021.006 Windows Remote Management:** what Remote Desktop Users and Remote Management Users membership enables.
- **T1003.002 Security Account Manager / T1003.003 NTDS:** credential theft enabled by Backup Operators.
