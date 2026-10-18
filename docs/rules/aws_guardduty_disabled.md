# AWS GuardDuty Detector Deleted, Disabled or Detached

| | |
|---|---|
| **Rule** | [`rules/aws/defense_impairment/aws_guardduty_disabled.yml`](../../rules/aws/defense_impairment/aws_guardduty_disabled.yml) |
| **Rule ID** | `a7697b3c-9881-4736-a7d1-b7941065a969` |
| **Level** | high |
| **ATT&CK** | Defense Impairment: T1685 Disable or Modify Tools |
| **Log source** | AWS CloudTrail (GuardDuty management calls) |

## Summary

GuardDuty was turned off in an account or region, one of its protection features was switched off, or the link to the central GuardDuty administrator was cut. Each of these leaves activity in the account unwatched or invisible to the security team, and it's a common early step after gaining admin access. Planned changes happen but are rare, hence high.

## What it detects

All on `eventSource` `guardduty.amazonaws.com`:

- `DeleteDetector`: GuardDuty removed from the region
- `UpdateDetector` turning something off: `enable` false, any `features` entry or `additionalConfiguration` entry with status `DISABLED`, or one of the deprecated `dataSources` settings (`s3Logs`, `kubernetes.auditLogs`, `malwareProtection` EBS scanning) false
- `DisassociateFromAdministratorAccount` (and its older name `DisassociateFromMasterAccount`): a member account leaving its administrator
- `DisassociateMembers`, `DeleteMembers`, `StopMonitoringMembers`: the administrator dropping or no longer monitoring member accounts

Failed calls are included. In Sentinel the `UpdateDetector` settings are searched in the `RequestParameters` text (any `: false`, or `DISABLED` anywhere), which is equivalent because those are the only booleans and statuses in that request.

Not covered:

- **Organization-level changes** (`UpdateOrganizationConfiguration`, `DisableOrganizationAdminAccount`) that stop auto-enabling GuardDuty for accounts.
- **Malware Protection plans** for S3 (`DeleteMalwareProtectionPlan`) and **publishing destinations** (`DeletePublishingDestination`) that stop findings being exported.
- **Indirect breakage**, such as deleting the EventBridge rule or SNS topic that carries findings.

## Triage steps

1. **What changed.** `eventName` and `requestParameters`: a deleted detector or detached account is worse than one feature turned off. Note `errorCode`: a denied attempt still shows intent.
2. **Scope.** `awsRegion` and `recipientAccountId`; for member calls, `requestParameters.accountIds`. An attacker often repeats this across regions, so search the same caller for the same call in other regions.
3. **Who and from where.** `userIdentity` (role, session name, access key), `sourceIPAddress`, `userAgent`. Compare with the people and pipelines that normally manage GuardDuty.
4. **What else.** Search the same identity for other defense impairment in the same window: CloudTrail stopped or changed, Security Hub, Config or Detective turned off, GuardDuty filters or trusted IP lists changed (see the [findings suppressed rule](aws_guardduty_findings_suppressed.md)).
5. **Change records.** Account closure, region opt-out, a move to a new administrator account, or a cost decision on a feature.
6. **Decide.** A planned, recorded change can be closed. Otherwise turn GuardDuty back on, contain the identity and escalate.

## Known false positives

- **Account or region decommissioning.**
- **Cost decisions** to switch off individual features (S3 data events, EKS runtime, malware scanning).
- **Organization changes** moving members between administrator accounts.

Tune by the security team's GuardDuty-management role together with a change window, never by caller alone.

## Related techniques

- **T1685 Disable or Modify Tools:** the technique itself.
- **T1685.002 Cloud Log** ([CloudTrail rules](aws_cloudtrail_logging_stopped_or_deleted.md)): the logging side of the same goal.
- **T1078.004 Cloud Accounts:** the access usually needed first.
