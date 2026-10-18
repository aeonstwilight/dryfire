# AWS CloudTrail Trail Configuration or Event Selectors Changed

| | |
|---|---|
| **Rule** | [`rules/aws/defense_impairment/aws_cloudtrail_logging_config_changed.yml`](../../rules/aws/defense_impairment/aws_cloudtrail_logging_config_changed.yml) |
| **Rule ID** | `7ae0fb29-37b7-4845-837f-30282295bc84` |
| **Level** | medium |
| **ATT&CK** | Defense Impairment: T1685.002 Disable or Modify Cloud Log |
| **Log source** | AWS CloudTrail (management events, `cloudtrail.amazonaws.com`) |

## Summary

A CloudTrail trail's settings or event selectors were changed. The trail keeps running, so this is a quieter way to blind logging than stopping it: record only read events, drop management events, send logs to a bucket the attacker controls, or turn off log file validation. Most of these changes are routine admin work, hence medium.

## What it detects

CloudTrail events with `eventSource` `cloudtrail.amazonaws.com` and `eventName`:

- `UpdateTrail`: destination bucket or prefix, SNS topic, KMS key, multi-region, global service events, log file validation, CloudWatch Logs delivery
- `PutEventSelectors`: which events the trail records (management events on or off, read/write type, data events, excluded event sources)

The rule matches the call, not the new settings. Telling a harmful change from a routine one means reading inside `requestParameters`, which each SIEM stores differently, so it's left to triage (step 2). Failed calls are included.

Not covered:

- **Stopping or deleting a trail:** see [AWS CloudTrail Logging Stopped or Trail Deleted](aws_cloudtrail_logging_stopped_or_deleted.md).
- **`PutInsightSelectors`** (CloudTrail Insights only, not what's recorded) and **advanced event selectors on CloudTrail Lake** (`UpdateEventDataStore`).
- **Changes to the destination bucket or KMS key themselves** (S3 and KMS calls).

## Triage steps

1. **What changed.** Read `requestParameters`:
   - `PutEventSelectors`: `includeManagementEvents: false`, `readWriteType: ReadOnly`, or `excludeManagementEventSources` naming services such as `kms.amazonaws.com` or `rdsdata.amazonaws.com` all hide activity. Adding data events is usually harmless.
   - `UpdateTrail`: a new `s3BucketName` (check the bucket's account), `isMultiRegionTrail: false`, `includeGlobalServiceEvents: false` (IAM and STS events go missing), `enableLogFileValidation: false`, or a removed KMS key.
2. **Compare with the previous settings.** `GetEventSelectors` / `DescribeTrails` now, against your expected baseline or the last change. A change followed by a revert minutes later (as in the Stratus Red Team samples) can mean someone hid a short window.
3. **Who and from where.** `userIdentity`, `sourceIPAddress`, `userAgent`. Expected: the cloud or security team, or a known pipeline role. Unexpected: a developer role, a long-term user key, root.
4. **What happened while logging was reduced.** Activity by the same principal before and after. Events not recorded during the window won't be in CloudTrail; use other sources (GuardDuty, flow logs, S3 access logs).
5. **Decide.** A ticketed change that only adds or tunes data events can be closed. Any change that removes management events or global service events, or moves logs to another account, should be reverted and escalated unless approved.

## Known false positives

- **Administrators or infrastructure-as-code** adjusting trail settings, data event logging or selectors.
- **Cost tuning** that removes S3 object or Lambda data events from a trail.

Tune by principal plus trail name. Don't tune out changes that set `includeManagementEvents` to false.

## Related techniques

- **T1685.002 Disable or Modify Cloud Log:** the technique itself; see also the stopped-or-deleted rule.
- **T1078.004 Cloud Accounts:** the credentials used for the change.
- **T1537 Transfer Data to Cloud Account:** logs redirected to a bucket in another account.
