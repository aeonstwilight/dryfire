# AWS Root Account Console Login

| | |
|---|---|
| **Rule** | [`rules/aws/initial_access/aws_root_console_login.yml`](../../rules/aws/initial_access/aws_root_console_login.yml) |
| **Rule ID** | `9a6436aa-eb9e-481d-80e9-dcde10d7e757` |
| **Level** | high |
| **ATT&CK** | Initial Access, Privilege Escalation: T1078.004 Valid Accounts: Cloud Accounts |
| **Log source** | AWS CloudTrail (`ConsoleLogin`, `signin.amazonaws.com`) |

## Summary

Someone signed in to the AWS console as the account's root user, or tried to. Root can do anything in the account, including things no IAM policy can stop, so most organisations lock it away and use it only for a handful of account-level tasks. A root sign-in that isn't planned is a likely account takeover.

## What it detects

CloudTrail `ConsoleLogin` events where `userIdentity.type` is `Root`, whatever the result:

- **Success** (`responseElements.ConsoleLogin: Success`): someone is in as root.
- **Failure**: someone has the root email address and is trying passwords or MFA codes.

Not covered:

- **Root use without the console:** root access keys used with the API or CLI never create a `ConsoleLogin`. See [AWS Root Account Access Key Used](aws_root_access_key_used.md).
- **Organization member accounts with root access centralised** (no root credentials to sign in with): nothing to detect there.
- **Sign-ins by IAM users or federated roles**, even highly privileged ones.

## Triage steps

1. **Did it work?** Check `responseElements.ConsoleLogin`. A run of failures means password guessing or MFA attempts; a success after failures from the same IP is the worst case.
2. **Was MFA used?** `additionalEventData.MFAUsed`. A successful root sign-in with `MFAUsed: No` means the account has no root MFA or it was bypassed: treat as top priority whatever else you find.
3. **Is it expected?** Ask the account owner or check the break-glass process and change tickets. Root is only needed for a few tasks (billing settings, closing the account, some support plans, restoring access); anything else needs explaining.
4. **From where.** `sourceIPAddress` and `userAgent` against the owner's usual location and devices. Several IPs or countries in a short time (as in the T1586.003 sample) point to shared or stolen credentials.
5. **What root did next.** Search for `userIdentity.type: Root` events after the sign-in: MFA device changes (`DeactivateMFADevice`, `DeleteVirtualMFADevice`, `CreateVirtualMFADevice`), password policy changes, new IAM users or access keys, `CreateAccessKey` for root itself, billing or account contact changes, logging and GuardDuty changes.
6. **Decide.** A planned task by the owner, with MFA, from a known IP, can be closed. Otherwise: reset the root password, check and re-register MFA, remove any root access keys, review everything root did, and escalate.

## Known false positives

- **Account owners doing a task that requires root** (billing and account settings, closing the account, restoring IAM access).
- **Break-glass tests.**

Don't tune this rule out. If root sign-ins are routine in your environment, that's a finding in itself.

## Related techniques

- **T1078.004 Cloud Accounts:** the technique itself.
- **T1110 Brute Force / T1621 Multi-Factor Authentication Request Generation:** repeated failed root sign-ins.
- **T1556.006 Multi-Factor Authentication:** root MFA devices removed or replaced after sign-in.
- **T1098.001 Additional Cloud Credentials:** access keys or users created to keep access.
- **T1531 Account Access Removal:** owner locked out by password or contact changes.
