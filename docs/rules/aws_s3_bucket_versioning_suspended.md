# AWS S3 Bucket Versioning Suspended

| | |
|---|---|
| **Rule** | [`rules/aws/impact/aws_s3_bucket_versioning_suspended.yml`](../../rules/aws/impact/aws_s3_bucket_versioning_suspended.yml) |
| **Rule ID** | `4afa152b-653f-42e5-aedf-e6878312d7e2` |
| **Level** | medium |
| **ATT&CK** | Impact: T1490 Inhibit System Recovery |
| **Log source** | AWS CloudTrail (`s3.amazonaws.com`) |

## Summary

Someone suspended versioning on an S3 bucket. With versioning on, an overwritten or deleted object can be restored from an earlier version. Once it is suspended, new overwrites and deletes replace the object for good. Ransomware and destructive actors do this before encrypting or deleting a bucket's contents, the cloud version of deleting shadow copies (see the inhibit-system-recovery rule).

## What it detects

CloudTrail `eventSource` `s3.amazonaws.com`, `eventName` `PutBucketVersioning` and `requestParameters.VersioningConfiguration.Status` containing `Suspended`. Failed calls are included.

- `requestParameters.bucketName` is the bucket; `userIdentity` is who changed it.
- Versions that already exist are kept after suspension. Only changes made from then on lose their history, so look at what happens next.
- Sentinel and Elastic match `Suspended` anywhere in the request text (`RequestParameters` JSON, or Elastic's `aws.cloudtrail.request_parameters`). A bucket whose name contains "suspended" would also match there when versioning is enabled. Splunk and the Zircolite tests match the `Status` field itself.

Not covered:

- **MFA Delete turned off** (`MfaDelete: Disabled` with versioning left on). Rare, needs the root user with MFA, and has no public sample, so it was left out (owner decision).
- **Lifecycle rules that expire objects or old versions** (`PutBucketLifecycle`). That's a different behaviour and may become its own rule.
- **Deleting the objects or versions themselves** (`DeleteObject`/`DeleteObjects`): data events, often not logged.
- **Defender XDR:** no CloudTrail table ("unsupported", like the other AWS rules).

## Triage steps

1. **Which bucket, changed by whom?** Check `requestParameters.bucketName`, `userIdentity` and `errorCode`. A denied attempt is still an attempt.
2. **What's in the bucket?** Backups, logs, CloudTrail or Terraform state, or business records make it serious. Temporary or easily rebuilt data makes a cost-saving change plausible.
3. **Who made the change, and from where?** Look at `sourceIPAddress`, `userAgent` (console, CLI, SDK or IaC tool), and whether the caller's credentials are new or used from an unusual place.
4. **What happened next on the bucket?** Look for `PutBucketLifecycle` (expiring objects), `DeleteBucketPolicy`/`PutBucketPolicy`, `PutBucketEncryption` with an outside KMS key (see the KMS rule), and object deletes or overwrites where data events are logged. Also check for other buckets suspended by the same identity.
5. **Decide.** An approved change from the usual admin or pipeline identity, on a bucket that doesn't need its history, is benign: tune by bucket or identity. Otherwise turn versioning back on, restrict the caller's credentials and review what that identity did.

## Known false positives

- **Cost-saving changes** on buckets of temporary or easily rebuilt data.
- **Infrastructure-as-code** applying a configuration with versioning off.

## Related techniques

- **T1485 Data Destruction:** the deletes that suspension makes permanent.
- **T1486 Data Encrypted for Impact:** S3 ransomware that overwrites objects with encrypted copies.
- **T1490 on Windows:** shadow copy and backup deletion (the inhibit-system-recovery rule).
- **T1685 Disable or Modify Tools:** turning off other safety nets, such as CloudTrail or GuardDuty (the CloudTrail and GuardDuty rules).
