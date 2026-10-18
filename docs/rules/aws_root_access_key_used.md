# AWS Root Account Access Key Used

| | |
|---|---|
| **Rule** | [`rules/aws/persistence/aws_root_access_key_used.yml`](../../rules/aws/persistence/aws_root_access_key_used.yml) |
| **Rule ID** | `7c858b55-2567-4f38-ae41-7d838c00359a` |
| **Level** | high |
| **ATT&CK** | Persistence, Privilege Escalation: T1078.004 Valid Accounts: Cloud Accounts |
| **Log source** | AWS CloudTrail (any `AwsApiCall` event) |

## Summary

An API call was made with a long-term access key belonging to the account's root user. AWS recommends root has no access keys, so a root key in use is either one that should have been deleted or stolen root credentials being used from the CLI, an SDK or an attack tool. Unlike a console sign-in, this needs no password or MFA, and it's invisible to the root console login rule.

## What it detects

CloudTrail events where:

- `userIdentity.type` is `Root`
- `eventType` is `AwsApiCall`
- `userIdentity.accessKeyId` starts with `AKIA`, the prefix of long-term access keys

Calls made from a root console session use temporary keys (`ASIA`) and don't match: the console sign-in is caught by [AWS Root Account Console Login](aws_root_console_login.md). Calls AWS services make on root's behalf also use temporary keys.

Not covered:

- **Temporary credentials obtained with a root key** (`GetSessionToken` returns an `ASIA` key). The `GetSessionToken` call itself is made with the `AKIA` key and does match; follow the session from there.
- **Root key creation** (`CreateAccessKey` by root): matched only if that call is itself made with a root key. From the console, check the root login rule's follow-up activity.

## Triage steps

1. **Which key.** Note `userIdentity.accessKeyId`. In IAM (security credentials for root, or the credential report), check whether the account is supposed to have a root key at all and when it was created and last used.
2. **What it did.** `eventSource` and `eventName` for this and every other call with the same key. `GetCallerIdentity` first is typical of someone testing stolen credentials. IAM changes (`CreateUser`, `CreateAccessKey`, `AttachUserPolicy`), logging changes and data access (S3, Secrets Manager) need immediate action.
3. **From where and with what.** `sourceIPAddress` and `userAgent`: a known build server running an old script is very different from a residential or VPS IP running `aws-cli`, boto3 or a pentest tool.
4. **History.** When was the key last used before this, and from where? A key that was dormant for months and is suddenly used from a new IP is the classic leak pattern (code repository, CI logs, a laptop).
5. **Decide.** A known legacy integration: plan the migration to an IAM role and delete the key. Anything else: deactivate the key at once, reset the root password and MFA, review all activity by the key, and escalate.

## Known false positives

- **Legacy scripts or tools** still authenticating with a root key. These are findings in their own right: replace them with an IAM role or user and delete the key.

Tune only by exact `accessKeyId` plus `sourceIPAddress`, and only while the migration is tracked.

## Related techniques

- **T1078.004 Cloud Accounts:** the technique itself; see also the root console login rule.
- **T1552.001 Credentials In Files:** root keys leaked in code, config files or CI logs.
- **T1098.001 Additional Cloud Credentials:** further users or keys created with the root key.
