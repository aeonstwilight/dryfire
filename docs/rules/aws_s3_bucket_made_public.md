# AWS S3 Bucket Made Public by Policy or ACL

| | |
|---|---|
| **Rule** | [`rules/aws/collection/aws_s3_bucket_made_public.yml`](../../rules/aws/collection/aws_s3_bucket_made_public.yml) |
| **Rule ID** | `14f6e31c-4a50-41b6-9fea-2af3f5e71216` |
| **Level** | high |
| **ATT&CK** | Collection: T1530 Data from Cloud Storage |
| **Log source** | AWS CloudTrail (`PutBucketPolicy`, `PutBucketAcl`, `s3.amazonaws.com`) |

## Summary

An S3 bucket was opened to everyone, by a bucket policy that allows any principal or an ACL that grants the AllUsers or AuthenticatedUsers group. Attackers do this to pull data out without credentials, or to stage tools for download; it's also the classic accidental data leak. Either way the data may already be exposed.

## What it detects

Events from `s3.amazonaws.com`:

- **`PutBucketPolicy`** with an `Allow` statement whose `Principal` is `"*"` or `{"AWS": "*"}` (also as a list), with `Effect` before or after `Principal`
- **`PutBucketAcl`** granting anything to `.../groups/global/AllUsers` or `.../groups/global/AuthenticatedUsers` (any AWS account, so effectively public), through `x-amz-grant-*` headers, an XML access control policy (one grant or a list), or a canned ACL: `public-read`, `public-read-write`, `authenticated-read`

Failed calls are included. A `Deny` statement for `"*"` (such as the common TLS-only policy) doesn't match.

How each SIEM matches (see the pipeline files): Splunk searches the grant fields and the raw event JSON (policy and canned ACL); Sentinel searches the `RequestParameters` JSON text.

Not covered:

- **Public access through conditions:** a `"*"` principal limited by a `Condition` (`aws:SourceVpce`, `aws:PrincipalOrgID`) still matches; one that's public only through a condition doesn't change this. Check conditions in triage.
- **Statements where Principal and Effect aren't next to each other** (for example `Sid, Principal, Action, Effect`), and a policy sent as an escaped JSON string rather than an object.
- **Object ACLs** (`PutObjectAcl`), access points, and **cross-account but not public** grants (for example the Stratus Red Team backdoor policy in the corpus). Candidate follow-up rule.
- **Canned ACL shape:** the corpus has no canned-ACL example. The rule follows AWS's header name (`x-amz-acl`) as a single value or a list (tested synthetically). In Splunk, a bucket named exactly `public-read` would also match.

## Triage steps

1. **Is it really public?** Check whether Block Public Access is on for the bucket and account (`GetPublicAccessBlock`): if it is, the policy or ACL is stored but not effective. A Block Public Access change just before (the [related rule](aws_s3_public_access_block_disabled.md)) is a strong signal.
2. **What's exposed.** `requestParameters.bucketName`, the actions allowed (`s3:GetObject` is read; `s3:PutObject` or `public-read-write` lets anyone write) and any `Condition`. Find out what the bucket holds.
3. **Who and how.** `userIdentity`, `sourceIPAddress`, `userAgent` (console, CLI, IaC).
4. **Was data taken?** S3 server access logs or CloudTrail data events for the bucket: `GetObject` from unknown IPs or anonymous principals (`userIdentity.type` `AWSAccount` with `ANONYMOUS_PRINCIPAL`), `ListBucket` from outside.
5. **Decide.** A bucket meant to be public (website, dataset) and set up by its owner can be closed. Otherwise remove the policy statement or ACL grant, turn Block Public Access on, and escalate as a possible data exposure.

## Known false positives

- **Buckets meant to be public** (static websites, public datasets, CDN origins without origin access control).
- **Legacy setups** granting AllUsers read for website hosting or log delivery.

Tune by bucket name or tag together with the deploying role.

## Related techniques

- **T1530 Data from Cloud Storage:** the technique itself.
- **T1685 Disable or Modify Tools:** Block Public Access turned off first (see the related rule).
- **T1537 Transfer Data to Cloud Account / T1567.002 Exfiltration to Cloud Storage:** data moved out through the opened bucket.
- **T1619 Cloud Storage Object Discovery:** listing what the bucket holds.
