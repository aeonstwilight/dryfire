# Member Added to Local Administrators Group

| | |
|---|---|
| **Rule** | [`rules/windows/persistence/win_local_admin_group_member_added.yml`](../../rules/windows/persistence/win_local_admin_group_member_added.yml) |
| **Rule ID** | `2f487cc5-fa62-4eca-9403-419bbe64fe49` |
| **Level** | medium |
| **ATT&CK** | Persistence, Privilege Escalation: T1098 Account Manipulation |
| **Log source** | Security 4732 (requires "Audit Security Group Management") |

## Summary

An account or SID was added to the built-in local Administrators group. That gives full control of the host and survives password resets of other accounts. Attackers use it to keep or regain admin access. Legitimate adds are common too, so the value is in who was added, by whom, and how.

## What it detects

Security 4732 with `TargetSid` = `S-1-5-32-544` (`BUILTIN\Administrators`).

- **SID, not name:** matching on the well-known SID works on localized Windows (`Administrateurs`, `Administratoren`) and if the group is renamed.
- **`MemberName` is `-` for local accounts and built-in principals.** It's only filled in, as an LDAP DN, for domain accounts. Use `MemberSid` to identify who was added.

On domain controllers, `BUILTIN\Administrators` is the domain's built-in Administrators group. The same 4732 and SID apply there, with domain-wide impact.

Not covered:

- **Other privileged built-in groups:** Remote Desktop Users (`-555`), Backup Operators (`-551`), Remote Management Users (`-580`) and similar. Candidate follow-up rule.
- **Domain groups** (4728/4756: Domain Admins, Enterprise Admins and so on). Candidate follow-up rule.
- **Group membership changed without a 4732,** for example offline SAM edits, or GPO Restricted Groups where auditing is off.

## Triage steps

1. **Who was added (`MemberSid`).** These SIDs should get priority:
   - Guest (`…-501`), the built-in Administrator (`…-500`) on hosts where it should be disabled
   - built-in service principals: `S-1-5-18` SYSTEM, `S-1-5-19` LOCAL SERVICE, `S-1-5-20` NETWORK SERVICE
   - accounts created minutes earlier (4720 on the same host)
   - domain accounts with no business reason to be local admin on this host
2. **Who did it (`SubjectUserName`, `SubjectUserSid`, `SubjectLogonId`).** Pivot on the logon ID to the 4624: type 3 or 10 from another host, or a process (Sysmon 1) such as `net localgroup administrators <x> /add`, PowerShell `Add-LocalGroupMember`, or `net.exe` under `WmiPrvSE` (see the WMI rule).
3. **Is it policy?** A SYSTEM subject at GPO refresh time, matching the Restricted Groups or Intune local-admin policy for this host, is expected. Compare the member against the policy.
4. **What happened next.** Look for logons by the new member (4624), especially RDP (type 10) or network logons from unusual sources, and for further persistence: services, tasks, new accounts.
5. **Scope.** Search for the same member SID added on other hosts, and other 4732s by the same subject.
6. **Decide.** A change matching policy or a ticketed helpdesk change can be closed; consider removing temporary admin afterwards. Built-in or service SIDs, Guest, freshly created accounts, or adds from an unexpected remote session should be escalated.

## Known false positives

- **GPO Restricted Groups and Intune local-admin policies** re-applying membership. These often appear as SYSTEM, sometimes repeatedly.
- **Helpdesk or deployment processes** granting temporary local admin.
- **Software installers** adding their service accounts to Administrators.

Tune by subject and member together, for example "SYSTEM adding the policy-defined admin group SID". Don't exclude the SYSTEM subject outright: an attacker running as SYSTEM produces the same subject.

## Related techniques

- **T1098.007 Additional Local or Domain Groups:** the specific sub-technique for this activity.
- **T1136.001 Local Account:** a new local account (4720) created just before being made admin.
- **T1078.003 Local Accounts:** later use of the new admin account.
- **T1484.001 Group Policy Modification:** attackers pushing admin membership through GPO.
- **T1021.001 Remote Desktop Protocol:** a common next step with the new admin account.
- **T1047 Windows Management Instrumentation:** remote `net localgroup` via WMI.
