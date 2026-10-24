# AWS IAM Login Profile Created or Updated

| | |
|---|---|
| **Rule** | [`rules/aws/persistence/aws_iam_login_profile_created_or_updated.yml`](../../rules/aws/persistence/aws_iam_login_profile_created_or_updated.yml) |
| **Rule ID** | `9e065cb4-6741-4d3f-93ba-111bd2cdffe8` |
| **Level** | medium |
| **ATT&CK** | Persistence: T1098.001 Account Manipulation: Additional Cloud Credentials |
| **Log source** | AWS CloudTrail (`iam.amazonaws.com`) |

## Summary

Someone set a console password for an IAM user. `CreateLoginProfile` gives a user console access it may never have had (service and automation users often only have access keys); `UpdateLoginProfile` replaces a user's password. With IAM rights, an attacker uses this to get a working console login on an existing, trusted-looking user instead of creating a new one, which is easier to spot. The Atomic Red Team sample does exactly that, then signs in without MFA.

## What it detects

CloudTrail `eventSource` `iam.amazonaws.com` and `eventName` `CreateLoginProfile` or `UpdateLoginProfile`, failed calls included.

- `requestParameters.userName` is the user getting the password; `userIdentity` is who set it.
- Users change their own password with `ChangePassword`, which isn't matched, so these calls are almost always one identity acting on another's account.
- The caller and target aren't compared in the rule: that comparison can't be expressed for Sentinel or Elastic (see the access-key rule), and it would rarely change the result. Compare them in triage.

Not covered:

- **Creating a brand-new user** with a password (`CreateUser` followed by `CreateLoginProfile` is caught by the second call).
- **Access keys** (`CreateAccessKey`): the access-key rule.
- **IAM Identity Center (SSO) users:** their passwords are managed outside IAM.
- **Defender XDR:** no CloudTrail table ("unsupported", like the other AWS rules).

## Triage steps

1. **Whose password, set by whom?** Compare `requestParameters.userName` with `userIdentity`. Check `errorCode`: a denied attempt is still an attempt.
2. **Should that user have console access at all?** A service or automation account (keys only until now) getting a password is a strong sign. So is a dormant user, or one with powerful permissions.
3. **Who set it, and from where.** `sourceIPAddress`, `userAgent`, and whether the caller's credentials are new (a recent `CreateAccessKey`) or used from an unusual place.
4. **What happened next.** A `ConsoleLogin` by the target user soon after, especially without MFA (the console-login-without-MFA rule), from the same IP as the caller; MFA removed from the user (the MFA rule); policy changes on the user.
5. **Decide.** A helpdesk reset with a ticket, from the usual admin identity, is benign: tune by that identity. Otherwise delete the login profile (or reset it under the owner's control), rotate the caller's credentials and review what both identities did.

## Known false positives

- **Helpdesk or administrator password resets.**
- **Onboarding** that gives new IAM users console access (usually with `passwordResetRequired: true`).

## Related techniques

- **T1078.004 Valid Accounts: Cloud Accounts:** the console login that usually follows (the console-login-without-MFA rule).
- **T1098.001:** the same technique with access keys (the access-key rule).
- **T1556.006 Multi-Factor Authentication:** MFA removed from the same user (the MFA rule).
- **T1136.003 Create Account: Cloud Account:** the noisier alternative of making a new user.
