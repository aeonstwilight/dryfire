# Directory Secrets Replicated by a Non-Machine Account (DCSync)

| | |
|---|---|
| **Rule** | [`rules/windows/credential_access/win_dcsync_replication_by_non_machine_account.yml`](../../rules/windows/credential_access/win_dcsync_replication_by_non_machine_account.yml) |
| **Rule ID** | `e9dd1d82-d0b0-48b3-bac2-831dfe3c3d32` |
| **Level** | high |
| **ATT&CK** | Credential Access: T1003.006 DCSync |
| **Log source** | Security 4662 on domain controllers (Audit Directory Service Access, SACL on the domain object) |

## Summary

An account that isn't a computer account used the directory replication right that returns secrets. That is what DCSync does (Mimikatz `lsadump::dcsync`, Impacket `secretsdump`, Empire, Covenant): it asks a DC for password hashes as if it were another DC, often for `krbtgt` or Domain Admins. Treat it as domain-wide credential theft until shown otherwise.

## What it detects

Security 4662 where `Properties` contains one of:

- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`: DS-Replication-Get-Changes-All
- `89e95b76-444d-4c62-991a-0facbeda640c`: DS-Replication-Get-Changes-In-Filtered-Set

and `SubjectUserName` doesn't end in `$`.

A DCSync logs plain Get-Changes (`1131f6aa`) as well, usually twice. Only the secrets right is matched, so each DCSync gives one hit, and directory-sync tools that use Get-Changes alone don't fire.

Not covered:

- **DCSync with a computer account.** Every account ending in `$` is excluded: a DC's own replication, but also a member server or attacker-created computer account that was granted replication rights, or a relayed DC account. A DC allow-list would close this, but it's environment-specific.
- **DCs without the audit setting or SACL.** No 4662, no detection. Network-level DRSUAPI `DsGetNCChanges` from a non-DC IP (Zeek, IDS) is the complementary view.
- **Granting the rights** (5136 on the domain object's `nTSecurityDescriptor`, e.g. PowerView `Add-DomainObjectAcl -Rights DCSync`): a separate detection.

## Triage steps

1. **Who and from where.** Find the 4624 for `SubjectLogonId` on the same DC to get the source IP and workstation. A user or service account replicating from a workstation or a non-DC server is the attack pattern.
2. **Is the account expected to replicate?** Compare with the accounts that legitimately hold these rights: Entra Connect (`MSOL_…`, running on the Entra Connect server), and known backup, migration or AD auditing tools. Check the source host matches the tool's server.
3. **When did it get the right?** Look for recent 5136 changes to the domain object's security descriptor, or new group membership (4728/4756) for the account. A right granted shortly before use is a strong sign.
4. **Scope.** Search all DCs for the same account and source in 4662, and for follow-on use: Kerberos tickets for privileged accounts from unusual hosts (4768/4769), pass-the-hash logons (4624 type 3 with NTLM), golden tickets.
5. **Decide.** Unknown account or source: treat as full credential compromise (reset `krbtgt` twice, privileged accounts, the account used). Known sync tool from its own server: tune by account name plus source host.

## Known false positives

- **Microsoft Entra Connect** (Azure AD Connect) password hash sync account (`MSOL_…`), or other identity sync products granted replication rights. Left to local tuning (owner decision), since the account name can be changed.
- **Backup, migration or AD auditing tools** that replicate with a service account.

Tune by exact account name and source host, never by the GUID alone.

## Related techniques

- **T1003.003 NTDS:** the offline route to the same hashes (the hive and NTDS dumping rule).
- **T1098 Account Manipulation:** granting replication rights before a DCSync (5136).
- **T1558.001 Golden Ticket:** the usual next step with the `krbtgt` hash.
- **T1550.002 Pass the Hash:** using the stolen hashes directly.
