# AWS IAM MFA Device Deactivated

| | |
|---|---|
| **Rule** | [`rules/aws/persistence/aws_iam_mfa_device_deactivated.yml`](../../rules/aws/persistence/aws_iam_mfa_device_deactivated.yml) |
| **Rule ID** | `45a54481-d14b-4ff9-8ef3-143924f93424` |
| **Level** | medium |
| **ATT&CK** | Persistence, Credential Access: T1556.006 Modify Authentication Process: Multi-Factor Authentication |
| **Log source** | AWS CloudTrail (`iam.amazonaws.com`) |

## Summary

An MFA device was taken off an IAM user or the root user. After that a password is enough to sign in, or the attacker can register a device of their own and lock the real owner out. It's a common step in account takeover: get the password (or IAM rights over the user), remove MFA, sign in, then add persistence.

## What it detects

CloudTrail `eventSource` `iam.amazonaws.com` and `eventName` `DeactivateMFADevice`, failed calls included.

- AWS requires an assigned device to be deactivated before it can be deleted, so every removal of a working device includes this call: one alert per removal.
- `DeleteVirtualMFADevice` is not matched. It follows a deactivation (see triage), but on its own it is also used to clean up devices that were never assigned, such as abandoned enrollments.
- `requestParameters.userName` is the user whose device was removed (`AWS ROOT USER` for root); `userIdentity` is who did it.

Not covered:

- **Deleting the user's login profile or access keys,** or attaching a policy that no longer requires MFA: other rules or patterns.
- **IAM Identity Center (SSO) MFA:** managed in Identity Center, not with this IAM call.
- **Defender XDR:** no CloudTrail table ("unsupported", like the other AWS rules).

## Triage steps

1. **Whose device, and who removed it?** Compare `requestParameters.userName` with `userIdentity`. A user removing another user's device, or root's device being removed, needs a reason. Check `errorCode`: a denied attempt is still an attempt.
2. **Where from?** `sourceIPAddress` and `userAgent` against the identity's usual ones. A console session from a new location or a fresh access key stands out.
3. **What came next for that user?** Within minutes to hours: `EnableMFADevice` or `CreateVirtualMFADevice` with a new device (a replacement, or the attacker's own), `ConsoleLogin` without MFA (the console-login rule), `CreateLoginProfile`/`UpdateLoginProfile`, new access keys, policy changes.
4. **Was it expected?** A helpdesk ticket for a lost phone, with the user re-enrolling from their usual location, is benign. Ask the user if in doubt.
5. **Decide.** Unexpected removal: re-enroll MFA under the user's control, reset the password, rotate access keys, and review what the identity that removed it has done. Tune helpdesk or offboarding automation by its exact identity.

## Known false positives

- **Phone replacement:** the user deactivates the old device and enables a new one shortly after.
- **Helpdesk or admins resetting MFA** for a locked-out user.
- **Offboarding automation** removing a leaving user's devices.

## Related techniques

- **T1078.004 Valid Accounts: Cloud Accounts:** the password-only login that usually follows (the console-login-without-MFA and root-login rules).
- **T1098.001 Additional Cloud Credentials:** new login profiles or access keys for the same user (the access-key rule).
- **T1621 Multi-Factor Authentication Request Generation:** MFA fatigue against users whose MFA is still on.
