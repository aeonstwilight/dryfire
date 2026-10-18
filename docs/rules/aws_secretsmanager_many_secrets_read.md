# AWS Secrets Manager Many Distinct Secrets Read by One Identity

| | |
|---|---|
| **Rule** | [`rules/aws/credential_access/aws_secretsmanager_many_secrets_read.yml`](../../rules/aws/credential_access/aws_secretsmanager_many_secrets_read.yml) |
| **Rule ID** | `5d4abf7c-6493-4770-aaba-f7f6085b5bf5` |
| **Level** | medium |
| **ATT&CK** | Credential Access: T1555.006 Cloud Secrets Management Stores |
| **Log source** | AWS CloudTrail (Secrets Manager) |

## Summary

One identity read the values of 10 or more different secrets within 10 minutes. Applications normally read the same few secrets over and over; reading many different ones in a short time is how stolen credentials get turned into more credentials. Deployment and rotation tooling does this too, hence medium.

## What it detects

A Sigma correlation rule (`value_count`) in two parts, in one file:

- **Base rule:** `GetSecretValue` and `BatchGetSecretValue` on `secretsmanager.amazonaws.com`, failed calls included.
- **Correlation:** 10 or more distinct `requestParameters.secretId` values per `userIdentity.arn` within 10 minutes.

A batch read is counted through the `GetSecretValue` record CloudTrail writes for each secret in the batch; the `BatchGetSecretValue` record itself has no `secretId`.

One alert per identity over the threshold, however long the burst lasts.

Engine differences:

- **Splunk** counts in fixed 10-minute buckets (`bin _time span=10m`). A burst split across a bucket boundary (say 6 secrets at 10:08 and 6 at 10:11) alerts in a sliding window but not in Splunk. Lower the threshold or use `streamstats` if that matters.
- **Sentinel:** pySigma-backend-kusto doesn't convert correlation rules, so no KQL is generated.
- **Distinct values:** a secret read once by name and once by ARN counts twice. Zircolite compares secret IDs ignoring case; Splunk's `dc()` doesn't.

Not covered:

- **Slow reads** below 10 secrets in 10 minutes.
- **Reads spread across several identities** or sessions (each counted separately; an assumed-role ARN includes the session name).
- **Secrets read outside Secrets Manager**, such as SSM Parameter Store (`GetParameter`, `GetParametersByPath`).

## Triage steps

1. **Which secrets.** List the `requestParameters.secretId` values in the window, and `errorCode`: many `AccessDeniedException` errors mean someone is probing what they can read.
2. **Who and from where.** `userIdentity` (role, session name, access key), `sourceIPAddress`, `userAgent`. An IP or user agent never seen for this identity points to stolen credentials. Compare with the identity's usual reads over the past weeks.
3. **Discovery first?** Search the same identity for `ListSecrets` and `DescribeSecret` just before.
4. **What did the secrets unlock?** Search for use of the credentials they hold: database logins, API keys used from new places, `AssumeRole` with keys from the secrets.
5. **Change records.** A deployment, rotation or migration job at that time explains it.
6. **Decide.** Known tooling can be closed and tuned. Otherwise contain the identity and rotate every secret read in the window.

## Known false positives

- **Deployment and configuration tools** reading all of an application's secrets at start-up.
- **Rotation, backup or migration jobs.**
- **Administrators** reviewing secrets.

Tune by role name for known automation, or raise the threshold for it, never by caller alone.

## Related techniques

- **T1555.006 Cloud Secrets Management Stores:** the technique itself.
- **T1078.004 Cloud Accounts:** the stolen identity usually used, and what the secrets often hold.
- **T1580 Cloud Infrastructure Discovery:** `ListSecrets` and `DescribeSecret` before the reads.
