# AWS S3 Block Public Access Removed or Weakened

| | |
|---|---|
| **Rule** | [`rules/aws/defense_impairment/aws_s3_public_access_block_disabled.yml`](../../rules/aws/defense_impairment/aws_s3_public_access_block_disabled.yml) |
| **Rule ID** | `c24e12aa-627b-478f-bf39-0f0ff162ea31` |
| **Level** | medium |
| **ATT&CK** | Defense Impairment: T1685 Disable or Modify Tools |
| **Log source** | AWS CloudTrail (S3 Block Public Access calls) |

## Summary

S3 Block Public Access was removed or partly turned off for a bucket or for the whole account. It overrides public bucket policies and ACLs, so turning it off is the step before a bucket can actually be made public. It's also done deliberately for public websites and datasets, hence medium; a public policy or ACL soon after on the same bucket is the high-severity signal (see the related rule).

## What it detects

- `DeleteBucketPublicAccessBlock` and `DeleteAccountPublicAccessBlock`: the configuration removed
- `PutBucketPublicAccessBlock` and `PutAccountPublicAccessBlock` with any of `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy` or `RestrictPublicBuckets` set to `false`

Failed calls are included. In Sentinel the four settings are searched in the `RequestParameters` text (any `: false`), which is equivalent here because these requests carry only those settings.

Not covered:

- **Access points and multi-region access points** with their own Block Public Access settings.
- **Organization-level controls** (SCPs, or S3 policies managed through AWS Organizations).

## Triage steps

1. **Bucket or account?** Account-level (`*AccountPublicAccessBlock`) affects every bucket and is more serious.
2. **Which protections.** For a `Put...`, read `requestParameters.PublicAccessBlockConfiguration`: `BlockPublicPolicy` and `RestrictPublicBuckets` off allow a public bucket policy; `BlockPublicAcls` and `IgnorePublicAcls` off allow public ACLs.
3. **What came next.** Search for `PutBucketPolicy` or `PutBucketAcl` on the same bucket (`requestParameters.bucketName`) shortly after. The [public policy or ACL rule](aws_s3_bucket_made_public.md) fires on those.
4. **Is it meant to be public?** Static website hosting, CDN origins and published datasets are legitimate; check the bucket's tags, owner and change records.
5. **Who and from where.** `userIdentity`, `sourceIPAddress`, `userAgent`.
6. **Decide.** A known public bucket set up by its owner can be closed. Otherwise turn the protection back on and escalate, especially at account level or for buckets holding data.

## Known false positives

- **Buckets meant to be public** (static websites, public datasets).
- **Infrastructure-as-code** applying a bucket's intended settings.

Tune by bucket name or tag together with the deploying role, never by caller alone.

## Related techniques

- **T1685 Disable or Modify Tools:** the technique itself (a security control turned off).
- **T1530 Data from Cloud Storage:** the data access a public bucket allows.
- **T1537 Transfer Data to Cloud Account:** exfiltration through a bucket opened to others.
