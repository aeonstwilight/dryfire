# Member Added to a Domain Admin Group

| | |
|---|---|
| **Rule** | [`rules/windows/persistence/win_domain_admin_group_member_added.yml`](../../rules/windows/persistence/win_domain_admin_group_member_added.yml) |
| **Rule ID** | `ae831178-fccd-46fd-b498-af3dc619d54b` |
| **Level** | high |
| **ATT&CK** | Persistence, Privilege Escalation: T1098.007 Account Manipulation: Additional Local or Domain Groups |
| **Log source** | Security 4728, 4756 and 4732 on domain controllers (requires "Audit Security Group Management") |

## Summary

An account was added to an Active Directory group that gives control of the domain or forest, or a direct path to it. This is the classic final step of a domain compromise and a common persistence move: one membership change survives password resets of every other account. Local and built-in groups are covered by [Member Added to Local Administrators Group](win_local_admin_group_member_added.md) and [Member Added to a Privileged Built-in Group Other Than Administrators](win_privileged_builtin_group_member_added.md).

## What it detects

| Group | Match | Event | Why it matters |
|---|---|---|---|
| Domain Admins | `TargetSid` ends `-512` | 4728 | full control of the domain |
| Enterprise Admins | `TargetSid` ends `-519` | 4756 | full control of the forest |
| Schema Admins | `TargetSid` ends `-518` | 4756 | can change the AD schema |
| Group Policy Creator Owners | `TargetSid` ends `-520` | 4728 | can create GPOs, a code-execution path to every linked host |
| Key Admins | `TargetSid` ends `-526` | 4728 | can write `msDS-KeyCredentialLink` (shadow credentials) on domain objects |
| Enterprise Key Admins | `TargetSid` ends `-527` | 4756 | the same, forest-wide |
| Cert Publishers | `TargetSid` ends `-517` | 4732 | can publish certificates to AD, an AD CS abuse path |
| DnsAdmins | `TargetUserName` is `DnsAdmins` | 4732 | can make the DNS service on a DC load an arbitrary DLL |

The RID match works whatever the domain SID or group display name. The event ID is part of the match: a 4729/4757/4733 (removal) doesn't fire.

Not covered:

- **DnsAdmins renamed or localized.** It has no fixed RID, so it's matched by name only. If your domain uses another name, add it.
- **Protected Users (`-525`).** Left out on purpose: adding an account there restricts it rather than granting rights.
- **Nested groups.** Adding a group, or adding a member to a group that is itself a member of Domain Admins, logs the event for the intermediate group only.
- **Other privileged paths:** `adminCount`/AdminSDHolder ACL changes, DCSync rights granted directly, or delegated control over these groups. Those need directory-change auditing (5136), not membership events.
- **Built-in domain groups** (Administrators, Account/Server/Backup/Print Operators on DCs): covered by the two local/built-in group rules.

## Triage steps

1. **Which group, which DC.** Enterprise Admins, Schema Admins and Domain Admins are the most urgent. Note the DC that logged it.
2. **Who was added (`MemberName`, `MemberSid`).** Look for newly created accounts (4720 shortly before), computer accounts (`$`), service accounts, and disabled or dormant accounts recently re-enabled (4722) or with a reset password (4724).
3. **Who made the change (`SubjectUserName`, `SubjectLogonId`).** Check that this account normally manages privileged groups. Pivot on the logon ID to the 4624 on the DC: source host and logon type. A change from a workstation, a server that isn't an admin jump host, or outside admin hours stands out.
4. **Is it planned?** Compare with change tickets and your privileged access process. Membership changes made by a PAM or identity tool should come from its service account.
5. **What happened next.** Logons by the new member to DCs or tier-0 systems, DCSync-style replication requests (4662 with the replication GUIDs), new GPOs or GPO edits, DNS `ServerLevelPluginDll` changes (for DnsAdmins), or certificate requests (for Cert Publishers and Key Admins).
6. **Decide.** Escalate anything not matched to a change record. Removing the member isn't enough on its own: assume the account was used and review what it touched.

## Known false positives

- **Planned onboarding or role changes** by identity administrators.
- **PAM or just-in-time access tools** that add and remove members on a schedule. Tune by the tool's service account as the subject together with the group, and keep the matching removal (4729/4757) as evidence the window closed.
- **AD CS installation** adding the CA server's computer account to Cert Publishers.

Don't tune by member or group alone.

## Related techniques

- **T1098 Account Manipulation:** the parent technique.
- **T1136.002 Domain Account:** new domain accounts created just before being added.
- **T1078.002 Domain Accounts:** use of the privileged account afterwards.
- **T1003.006 DCSync:** a common next step with Domain or Enterprise Admins rights.
- **T1484.001 Group Policy Modification:** what Group Policy Creator Owners membership enables.
- **T1574.001 DLL:** the DnsAdmins `ServerLevelPluginDll` DLL load on a DC.
- **T1649 Steal or Forge Authentication Certificates:** AD CS and shadow-credential abuse enabled by Cert Publishers and Key Admins.
