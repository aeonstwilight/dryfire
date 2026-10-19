# AWS S3 Bucket Policy Grants Access to a Whole AWS Account

| | |
|---|---|
| **Rule** | [`rules/aws/exfiltration/aws_s3_bucket_policy_cross_account_access.yml`](../../rules/aws/exfiltration/aws_s3_bucket_policy_cross_account_access.yml) |
| **Rule ID** | `aaea9f88-f95f-4727-b382-dc24e163f547` |
| **Level** | medium |
| **ATT&CK** | Exfiltration: T1537 Transfer Data to Cloud Account |
| **Log source** | AWS CloudTrail (S3 `PutBucketPolicy`) |

## Summary

A bucket policy now lets a whole AWS account read or write the bucket. Anyone in that account whose IAM permissions allow S3 can then use the bucket, so this is how data gets a quiet path out to an attacker's account, and it survives credential rotation in the victim account. Cross-account sharing is also a normal multi-account pattern, hence medium.

## What it detects

- `PutBucketPolicy` on `s3.amazonaws.com`, failed calls included
- the policy has an `Allow` statement, and a principal that is a whole account: `arn:aws:iam::<account>:root` or a bare 12-digit account ID
- the Allow and the account principal are not required to be in the same statement (rare mismatch: a Deny for an account next to an unrelated Allow)

Limits:

- **No same-account check.** The account ID is inside the policy text, so it can't be compared with the bucket's own account (`recipientAccountId`). A grant to the bucket's own account root also matches; check it in triage.
- **Not covered:** grants to single roles or users in another account; policies whose `Statement` is a single object rather than a list (the pattern reads the statement list); bucket ACL grants to another account's canonical ID; access points.
- **`Principal: "*"`** is the [public bucket rule](aws_s3_bucket_made_public.md).

Engine notes: the patterns accept `:` or `=` and optional quotes, so they match CloudTrail's JSON (Splunk `_raw`, Sentinel `RequestParameters`), Zircolite's text and Elastic's `Map.toString()` text. `"AWS"` must be a whole key, so `"AWS:SourceAccount"` conditions in service-delivery policies don't match.

## Triage steps

1. **Which account.** Read the principal from `requestParameters.bucketPolicy`. Same as `recipientAccountId`? Then it's a same-account grant (unusual but not cross-account). Otherwise: is the account in your organization, or a known partner?
2. **What it can do.** `Action` and `Resource`: read (`GetObject`, `ListBucket`) on a data bucket is the exfiltration case; `s3:*` or write access is worse.
3. **What's in the bucket.** Data classification, size, recent writes. A bucket that just got sensitive data is more urgent.
4. **Who and from where.** `userIdentity`, `sourceIPAddress`, `userAgent`; `errorCode` for denied attempts. Compare with the people and pipelines that manage this bucket.
5. **Was it used?** With S3 data events or server access logs, look for requests from the granted account after the change.
6. **Decide.** Known sharing can be closed and tuned by bucket and account ID. Otherwise remove the statement, review access since the change, and escalate.

## Known false positives

- **Planned cross-account sharing:** central log archive, data sharing between accounts in the organization, partner exchange.
- **Infrastructure-as-code** applying the intended policy.

Tune by bucket name together with the granted account ID, never by caller alone.

## Related techniques

- **T1537 Transfer Data to Cloud Account:** the technique itself.
- **T1530 Data from Cloud Storage:** reading the bucket's data.
- **T1098 Account Manipulation:** a resource-policy backdoor as persistence.
