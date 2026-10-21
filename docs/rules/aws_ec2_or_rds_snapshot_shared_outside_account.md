# AWS EBS Snapshot, AMI or RDS Snapshot Shared With Another Account or Made Public

| | |
|---|---|
| **Rule** | [`rules/aws/exfiltration/aws_ec2_or_rds_snapshot_shared_outside_account.yml`](../../rules/aws/exfiltration/aws_ec2_or_rds_snapshot_shared_outside_account.yml) |
| **Rule ID** | `7777bf04-d54f-4b7e-b3c8-38cc2b47a26b` |
| **Level** | medium |
| **ATT&CK** | Exfiltration: T1537 Transfer Data to Cloud Account |
| **Log source** | AWS CloudTrail (`ec2.amazonaws.com`, `rds.amazonaws.com`) |

## Summary

A disk image left the account: an EBS snapshot, an AMI or an RDS snapshot was shared with another AWS account, an organization or OU, or with everyone. The receiving account can copy it and read everything on it (files, databases, secrets on disk) without touching the source account again. It's a quiet, bulk way to steal data, used by Stratus Red Team and real attackers alike.

## What it detects

- **EBS snapshot / AMI:** `ModifySnapshotAttribute` or `ModifyImageAttribute` whose `createVolumePermission.add.items` or `launchPermission.add.items` list isn't empty. Each item is a `userId` (an account), an `organizationArn`/`organizationalUnitArn`, or `group: all` (public).
- **RDS:** `ModifyDBSnapshotAttribute` or `ModifyDBClusterSnapshotAttribute` with a non-empty `valuesToAdd` (account IDs or `all`).
- A snapshot can't be shared with its own account, so every added entry means another account or the public.
- Removing permissions (`remove`, `valuesToRemove`), an empty `add` and read calls don't match. Failed calls do, on purpose.

How the list is matched: one pattern per list that gives the same result on the list's own text (Zircolite), the raw event JSON (Splunk, which splits list items into `{}` fields it can't run a regex on), Sentinel's `RequestParameters` JSON and Elastic's `Map.toString()` text in `aws.cloudtrail.request_parameters`. `make validate` checks all three engines.

Not covered:

- **Copying instead of sharing:** `CopySnapshot`/`CopyImage` into another account or Region the attacker controls, `CreateStoreImageTask` to S3, or exporting an RDS snapshot to S3 (`StartExportTask`).
- **Turning off EC2's "block public access" for snapshots or AMIs** (`DisableSnapshotBlockPublicAccess`, `DisableImageBlockPublicAccess`): a related weakening, not a share.
- **Other shareable resources:** Redshift, Aurora clones, Backup vaults, S3 buckets (the S3 rules).
- **Defender XDR:** no CloudTrail table ("unsupported", like the other AWS rules).

## Triage steps

1. **Who gets it?** Read the added entries in `requestParameters`. `group: all` or `valuesToAdd: ["all"]` (public) is the most urgent: anyone can copy it now. For an account ID, check whether it belongs to your organization (`organizations:ListAccounts`) or a known partner.
2. **What's on it?** Look up the snapshot, AMI or DB snapshot: the source volume, instance or database, its tags and what it holds. Production databases, domain controllers or anything with customer data raise the stakes.
3. **Who shared it, and from where.** `userIdentity`, `sourceIPAddress`, `userAgent`. Compare with the team that normally publishes images. A new access key, an unusual role session or a console login without MFA (the console-login rule) stand out.
4. **What else did they do?** `CreateSnapshot`/`CreateImage`/`CreateDBSnapshot` just before (snapshotting a target in order to share it), `CopySnapshot` from the other side, KMS key policy changes granting the other account decrypt rights on an encrypted snapshot, and similar shares of other resources.
5. **Contain.** Revoke the share (`remove` / `valuesToRemove`) at once if it isn't expected; for public shares, assume it was copied. Then check the identity's other activity.
6. **Decide.** Sharing to your own build, backup or DR accounts, or a vendor publishing public AMIs on purpose, is benign: tune by identity and target account.

## Known false positives

- **Sharing with the organization's own accounts** (build pipelines distributing golden AMIs, backup or disaster-recovery accounts) or with a vendor.
- **Public AMIs published on purpose** by software vendors.

## Related techniques

- **T1530 Data from Cloud Storage** and the S3 rules: the bucket equivalent of this exposure.
- **T1578.001 Create Snapshot:** creating the snapshot that's then shared.
- **T1098.003 Additional Cloud Roles / KMS policy changes:** granting the other account access to the encryption key.
- **T1485 Data Destruction:** snapshots deleted after exfiltration (and the KMS key rule).
