# AWS KMS Key Disabled, Scheduled for Deletion or Key Material Deleted

| | |
|---|---|
| **Rule** | [`rules/aws/impact/aws_kms_key_disabled_or_deletion_scheduled.yml`](../../rules/aws/impact/aws_kms_key_disabled_or_deletion_scheduled.yml) |
| **Rule ID** | `265210b7-378d-4537-a514-926621c5bca3` |
| **Level** | medium |
| **ATT&CK** | Impact: T1485 Data Destruction |
| **Log source** | AWS CloudTrail (management events, `kms.amazonaws.com`) |

## Summary

Someone made a KMS key unusable. Everything encrypted under it (S3 objects, EBS volumes and snapshots, RDS databases, Secrets Manager secrets, application data) can't be decrypted while the key is disabled, and is gone for good once a scheduled deletion completes. Attackers with KMS rights use this to destroy data or hold it to ransom. A scheduled deletion can still be cancelled until the waiting period ends (`pendingWindowInDays`, 7–30 days), so speed matters.

## What it detects

`eventSource` `kms.amazonaws.com` and `eventName` one of:

- `ScheduleKeyDeletion`: the key and its data are lost after the waiting period.
- `DisableKey`: the key stops working until it's re-enabled.
- `DeleteImportedKeyMaterial`: a key with imported (BYOK) key material becomes unusable at once, until the same material is imported again.

Failed calls (`errorCode` set) are included on purpose: a denied attempt is still worth a look.

Not covered:

- **Locking the owner out** with `PutKeyPolicy` (a policy that removes the account's own access) or re-encrypting data under an attacker-held key (T1486). Different patterns, not matched here.
- **Keys deleted through other services** without these calls, and multi-Region replica keys removed by deleting the primary (`ScheduleKeyDeletion` on the primary is still caught).
- **Defender XDR:** no CloudTrail table ("unsupported", like the other AWS rules).

## Triage steps

1. **Did it work?** Check `errorCode`. A denied call means the identity tried something it isn't allowed to do: find out why. For a successful `ScheduleKeyDeletion`, note `pendingWindowInDays` and the deletion date in `responseElements`. **Cancel the deletion (`CancelKeyDeletion`) while you investigate** if there's any doubt.
2. **Which key, and what does it protect?** Look up the key (`requestParameters.keyId`): alias, description, tags, and which resources use it (S3 bucket encryption, EBS default encryption, RDS, Secrets Manager, CloudTrail log encryption). A key protecting production data, backups or CloudTrail logs raises the stakes.
3. **Who did it.** `userIdentity` (user, role, session name), `sourceIPAddress` and `userAgent`. Compare with the key's owners and the usual change process. A console session or CLI call from an unfamiliar IP, a newly created access key, or a role assumed from another account are red flags.
4. **What else did that identity do?** Look for the surrounding ransomware or destruction pattern: `PutKeyPolicy` on the same key, mass `DeleteObject`/`DeleteSnapshot`, S3 lifecycle or versioning changes, `StopLogging` on CloudTrail, new IAM users or access keys.
5. **Decide.** A planned retirement with a change record and the key owners' sign-off is benign; tune by the identity and key alias used for it. Anything else: cancel or re-enable, contain the identity, and check the data the key protects.

## Known false positives

- **Planned key retirement** or clean-up of unused keys by the key owners.
- **Infrastructure-as-code** (Terraform, CloudFormation, CDK) destroying a stack that owns a key, which schedules its deletion.
- **Temporary disabling** during a key rotation or incident drill.

## Related techniques

- **T1486 Data Encrypted for Impact:** re-encrypting data under an attacker's key, the other KMS ransomware pattern.
- **T1490 Inhibit System Recovery:** deleting backups and snapshots alongside the key.
- **T1685 Disable or Modify Tools:** stopping CloudTrail or GuardDuty first (the CloudTrail and GuardDuty rules).
- **T1098.001 Additional Cloud Credentials:** new access keys created to carry out the attack (the access-key rule).
