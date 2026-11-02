# AWS IAM Access Key Created for Another User

| | |
|---|---|
| **Rule** | [`rules/aws/persistence/aws_iam_access_key_created_for_other_user.yml`](../../rules/aws/persistence/aws_iam_access_key_created_for_other_user.yml) |
| **Rule ID** | `cf22be98-14d9-48b3-920a-ff0be93c27e9` |
| **Level** | medium |
| **ATT&CK** | Persistence: T1098.001 Account Manipulation: Additional Cloud Credentials |
| **Log source** | AWS CloudTrail (`iam.amazonaws.com`) |

## Summary

Someone created a long-term access key for an IAM user other than themselves. With a role or one user's credentials, an attacker can mint keys for another (often more privileged) user and keep access after the original credentials are found and rotated. It's also routine provisioning, so the rule is medium and triage hinges on who, for whom, and why.

## What it detects

`CreateAccessKey` events from `iam.amazonaws.com` where `requestParameters.userName` is set and isn't the caller's own `userIdentity.userName`:

- an IAM user creating a key for a different user
- a role (assumed role, federated session) creating a key for an IAM user. Roles have no `userName` of their own, so these always match. The robustness check shows it: rewriting the samples' callers as assumed roles adds 2 hits (`ct_assumed_role`: 68/66), the calls where an IAM user had created a key for itself.

Failed calls are included (`AccessDenied`, `NoSuchEntityException`): attempts against protected or made-up users (such as `root` in the test data) look like probing.

Not covered:

- **Users creating their own keys** (no target named, or naming themselves).
- **Other ways to get credentials for another user:** `CreateLoginProfile` / `UpdateLoginProfile` (console password), `UpdateAccessKey` (reactivating an old key), adding an MFA device, or role trust changes.
- **Sentinel:** declared unsupported. The target user only exists inside `RequestParameters` JSON text, so the comparison can't be mapped (see `pipelines/unsupported_targets.yml`).

## Triage steps

1. **Who created it.** `userIdentity.type` and `arn`. For a role, `userIdentity.sessionContext.sessionIssuer.userName` is the role; follow its `AssumeRole` (or SAML/OIDC federation) back to the person or system behind it.
2. **For whom.** `requestParameters.userName`. What can that user do (attached and group policies)? A key for an admin, break-glass or rarely used user is far worse than one for a service account that rotates keys routinely.
3. **Did it work?** `errorCode`. On success, `responseElements.accessKey.accessKeyId` is the new key: search for every call made with it since.
4. **Context.** `sourceIPAddress`, `userAgent` (console, CLI, SDK, Terraform, an attack tool), time, and whether it matches a ticket or the identity team's automation.
5. **What else the caller did.** Other IAM changes in the same session (`CreateUser`, `AttachUserPolicy`, `PutUserPolicy`, `AddUserToGroup`), logging changes, and discovery calls (`ListUsers`, `GetAccountAuthorizationDetails`).
6. **Decide.** Ticketed provisioning by the identity team or its automation role can be closed. Otherwise: deactivate the new key, review the caller's credentials, and escalate.

## Known false positives

- **Administrators or identity tooling** provisioning keys for service users.
- **Central key-rotation automation** running as a role.

Tune by caller (role ARN or user) plus target user pattern, not by caller alone.

## Related techniques

- **T1098.001 Additional Cloud Credentials:** the technique itself.
- **T1078.004 Cloud Accounts:** the new key used afterwards.
- **T1087.004 Cloud Account:** user discovery before choosing a target.
