# AWS IAM Administrator-Level Policy Granted

| | |
|---|---|
| **Rule** | [`rules/aws/privilege_escalation/aws_iam_admin_policy_granted.yml`](../../rules/aws/privilege_escalation/aws_iam_admin_policy_granted.yml) |
| **Rule ID** | `707cf754-3654-4dd6-bd26-03b1ac04a968` |
| **Level** | high |
| **ATT&CK** | Privilege Escalation, Persistence: T1098.003 Account Manipulation: Additional Cloud Roles |
| **Log source** | AWS CloudTrail (`iam.amazonaws.com`) |

## Summary

A user, role or group was given administrator-level permissions, or an existing managed policy was switched to another stored version. This is the usual step after initial access in AWS: turn a limited foothold into full control of the account, or make sure a backdoor identity has it.

## What it detects

IAM events (`eventSource` `iam.amazonaws.com`), in three branches:

- **Managed admin policy attached:** `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy` with `policyArn` ending in `:policy/AdministratorAccess` or `:policy/IAMFullAccess` (IAMFullAccess can grant itself anything). `AdministratorAccess-Amplify` and similar don't match.
- **Policy document granting everything:** `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy`, `CreatePolicyVersion` whose document has `"Action": "*"` or `"Action": "iam:*"`, including as the first item of an Action list.
- **Policy version rollback:** any `SetDefaultPolicyVersion`. The event doesn't show the version's content, so it's matched by name.

Failed calls are included.

Not covered:

- **Admin rights split across statements or actions** (`"Action": ["s3:*", "*"]` with `*` not first, a long list of services, or `NotAction` with an Allow). Review new or changed policies for those separately.
- **`CreatePolicy` on its own:** a new policy grants nothing until it's attached (attaching a customer-managed policy by ARN isn't matched either, since its name doesn't say what it grants).
- **Other ways to gain admin:** adding a user to an admin group (`AddUserToGroup`), changing a role's trust policy (`UpdateAssumeRolePolicy`), or passing an admin role to a new resource.

## Triage steps

1. **What was granted, to whom.** The target is `requestParameters.userName`, `roleName` or `groupName`; the grant is the `policyArn` or `policyDocument`. For `SetDefaultPolicyVersion`, look at the version now default (`GetPolicyVersion`) and compare it with the previous one.
2. **Who did it.** `userIdentity` (and the `sessionIssuer` for a role). An identity granting admin to itself, or to a user it just created, is the classic escalation chain.
3. **Did it work?** `errorCode`. `AccessDenied` on an admin grant still shows intent and the credentials used.
4. **Context.** `sourceIPAddress`, `userAgent` (console, CLI, Terraform, an attack tool), and whether it matches a change ticket or the IaC pipeline's role.
5. **What happened next.** Activity by the target identity after the grant, and other IAM changes by the caller (`CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, logging changes).
6. **Decide.** A ticketed change by the platform team or its pipeline role can be closed. Otherwise: detach or revert the policy (restore the old default version), review the caller's credentials, and escalate.

## Known false positives

- **Cloud administrators or infrastructure-as-code** granting admin rights intentionally.
- **Break-glass or bootstrap roles** set up with AdministratorAccess.

Tune by caller (the pipeline's role ARN) plus target, not by policy name alone.

## Related techniques

- **T1098.003 Additional Cloud Roles:** the technique itself.
- **T1078.004 Cloud Accounts:** the identity that gains the permissions.
- **T1098.001 Additional Cloud Credentials:** keys created for the newly privileged identity (see the access-key rule).
