# AWS IAM User Console Login Without MFA

| | |
|---|---|
| **Rule** | [`rules/aws/initial_access/aws_iam_user_console_login_without_mfa.yml`](../../rules/aws/initial_access/aws_iam_user_console_login_without_mfa.yml) |
| **Rule ID** | `69be0b46-0d31-4465-a7d2-d3763fb0a508` |
| **Level** | medium |
| **ATT&CK** | Initial Access: T1078.004 Valid Accounts: Cloud Accounts |
| **Log source** | AWS CloudTrail (`signin.amazonaws.com` ConsoleLogin) |

## Summary

An IAM user signed in to the AWS console with a password alone. Either the account has no MFA device (a gap an attacker with the password can walk through), or someone is using console credentials they shouldn't have, such as a login profile an attacker just added to an existing user (the Atomic Red Team sample does exactly this). Federated users and root are out of scope here.

## What it detects

CloudTrail `ConsoleLogin` with:

- `userIdentity.type` `IAMUser`
- `responseElements.ConsoleLogin` containing `Success`
- `additionalEventData.MFAUsed` `No`, matched with `(^|MFAUsed\\?"?\s*[:=]\s*\\?"?)No`

The pattern matches the bare value (Splunk, Zircolite), the JSON text in Sentinel's `AdditionalEventData` column and Elastic's `Map.toString()` text in `aws.cloudtrail.additional_eventdata` alike. It's keyed on `MFAUsed` because the same text also holds `MobileVersion`, which is usually `No` too. On Elastic the login result is the integration's `event.outcome`.

Not covered:

- **Root logins:** the root-login rule fires on every root console login.
- **Federated / IAM Identity Center sessions** (`AssumedRole`): MFA happens at the identity provider, and CloudTrail records `MFAUsed: No` for them.
- **Failed logins,** including attempts without MFA: see the brute-force and failed-login patterns.
- **API access with access keys,** which never involves MFA unless a policy requires `aws:MultiFactorAuthPresent`.
- **Defender XDR:** no CloudTrail table ("unsupported", like the other AWS rules).

## Triage steps

1. **Who and from where.** `userIdentity.userName`, `sourceIPAddress` and `userAgent`. Compare with the user's usual locations and devices. A new country, a hosting provider or VPN exit, or a first-ever console login for a user that normally only uses access keys stands out.
2. **Was the password just set?** Look for `CreateLoginProfile` or `UpdateLoginProfile` for this user shortly before, especially by another identity: that's an attacker giving themselves console access.
3. **Does the user have MFA at all?** Check for an MFA device, and for recent `DeactivateMFADevice` or `DeleteVirtualMFADevice` on the user (the MFA-removal rule). Removal followed by a password-only login is a takeover pattern.
4. **What did the session do?** Follow the session's API calls by `userIdentity.accessKeyId` (console sessions get a temporary key) or user and time: IAM changes, new access keys, security tooling changes, data access.
5. **Decide.** A known user without MFA from a normal location is a control gap: get MFA enrolled and enforce it by policy rather than tuning the alert. An unexpected login, or one after a profile or MFA change, is a likely account takeover: disable the login profile, rotate keys and review the session's activity.

## Known false positives

- **IAM users without an MFA device** in accounts that don't enforce MFA. Fix the gap rather than tune it out.
- **Break-glass IAM users** whose MFA device is deliberately kept offline (expect a change record).
- **Shared lab or training accounts.**

## Related techniques

- **T1098.001 Additional Cloud Credentials:** a login profile or access key created for the user first.
- **T1556.006 Multi-Factor Authentication:** MFA removed before the login (the MFA-removal rule).
- **T1110 Brute Force:** failed logins before a success.
- **T1078.004 root use:** the root-login and root-access-key rules.
