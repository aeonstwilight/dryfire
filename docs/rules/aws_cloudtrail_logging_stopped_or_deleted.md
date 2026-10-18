# AWS CloudTrail Logging Stopped or Trail Deleted

| | |
|---|---|
| **Rule** | [`rules/aws/defense_impairment/aws_cloudtrail_logging_stopped_or_deleted.yml`](../../rules/aws/defense_impairment/aws_cloudtrail_logging_stopped_or_deleted.yml) |
| **Rule ID** | `2f360a08-3e18-42f8-90bf-3252c52eaf1e` |
| **Level** | high |
| **ATT&CK** | Defense Impairment: T1685.002 Disable or Modify Cloud Log |
| **Log source** | AWS CloudTrail (management events, `cloudtrail.amazonaws.com`) |

## Summary

Someone stopped a CloudTrail trail, deleted one, or stopped or deleted a CloudTrail Lake event data store. Attackers do this to blind the account before or after the actions they don't want recorded. Any change to the logging itself on an account you monitor deserves a look, so this rule is high.

## What it detects

CloudTrail events with `eventSource` `cloudtrail.amazonaws.com` and `eventName`:

- `StopLogging`: the trail stays configured but stops delivering events
- `DeleteTrail`: the trail is removed
- `StopEventDataStoreIngestion` and `DeleteEventDataStore`: the same for CloudTrail Lake

Failed calls are included. A denied `StopLogging` (`errorCode` `AccessDenied`) still shows someone tried, often with stolen credentials testing what they can do.

Not covered:

- **Quieter changes to a trail** (`UpdateTrail`, `PutEventSelectors`): see [AWS CloudTrail Trail Configuration or Event Selectors Changed](aws_cloudtrail_logging_config_changed.md).
- **Tampering with the destination**: deleting or changing the S3 bucket, its policy or lifecycle, or the KMS key the trail uses. Those are S3 and KMS calls, not CloudTrail calls.
- **Organization trails changed from the management account**: the event is in the management account's logs, not the member account's.
- **Other logs**: CloudWatch log groups, VPC flow logs, GuardDuty (see the GuardDuty rule).

## Triage steps

1. **Did it work?** Check `errorCode`. With no error, the trail or data store named in `requestParameters` stopped recording: confirm with `GetTrailStatus` or the console, and restart it (`StartLogging`) if the activity isn't approved. With an error, the call failed, but the caller's other activity still needs the same review.
2. **Which trail.** `requestParameters.name` (or `eventDataStore`). Is it the account's main or organization trail, or a test trail? `StopLogging` on a trail named for a tool or test (as in the Stratus Red Team samples) right after a `CreateTrail` is lab activity.
3. **Who did it.** `userIdentity.type` and `userIdentity.arn`. For an assumed role, `userIdentity.sessionContext.sessionIssuer` gives the role; follow the `AssumeRole` call back to who assumed it. Root or a long-term IAM user key is a red flag.
4. **From where and with what.** `sourceIPAddress` and `userAgent`. Compare with the caller's usual IPs and tools. Console, CLI, an SDK, Terraform or a pentest tool (Stratus Red Team, Pacu) all leave different user agents.
5. **What happened around it.** Search the same principal and access key in the minutes before and after: IAM changes (new users, access keys, policies), `GetSecretValue`, S3 data access, `RunInstances`, other defence changes (GuardDuty, Config, flow logs). The gap in logging starts at this event, so check other sources too (GuardDuty findings, VPC flow logs, S3 server access logs).
6. **Decide.** A ticketed decommission by the cloud team or a pipeline's service role can be closed. Anything else: restart logging, disable the credentials used, and escalate.

## Known false positives

- **Planned decommissioning or replacement** of a trail or event data store.
- **Infrastructure-as-code** (Terraform, CloudFormation) tearing down a test or sandbox trail. In the test corpus every hit is lab activity of this kind.

Tune by principal (the pipeline's role ARN) plus account or trail name, never by `eventName` alone.

## Related techniques

- **T1685.002 Disable or Modify Cloud Log:** the technique itself; see also the configuration-change rule.
- **T1078.004 Cloud Accounts:** the valid credentials usually used for the call.
- **T1098.001 Additional Cloud Credentials:** new access keys often created around the same time.
- **T1530 Data from Cloud Storage / T1537 Transfer Data to Cloud Account:** the activity attackers want unlogged.
