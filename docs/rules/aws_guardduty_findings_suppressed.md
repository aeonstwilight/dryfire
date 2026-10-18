# AWS GuardDuty Findings Suppressed or Trusted IP List Changed

| | |
|---|---|
| **Rule** | [`rules/aws/defense_impairment/aws_guardduty_findings_suppressed.yml`](../../rules/aws/defense_impairment/aws_guardduty_findings_suppressed.yml) |
| **Rule ID** | `a0d77064-71b8-4858-80aa-420552dfd889` |
| **Level** | medium |
| **ATT&CK** | Defense Impairment: T1685 Disable or Modify Tools |
| **Log source** | AWS CloudTrail (GuardDuty management calls) |

## Summary

GuardDuty is still running, but some of its findings won't reach anyone: a suppression rule archives them automatically, a trusted IP list stops alerts for those addresses, or a threat list was removed. This is quieter than turning GuardDuty off. Security teams do make these changes to manage noise, hence medium.

## What it detects

All on `eventSource` `guardduty.amazonaws.com`:

- `CreateFilter` or `UpdateFilter` with `action` `ARCHIVE` (a suppression rule). A filter merely named or described "ARCHIVE" doesn't match.
- `CreateIPSet`, `UpdateIPSet`: a trusted IP list added or changed
- `DeleteIPSet`: a trusted IP list deleted
- `DeleteThreatIntelSet`: a threat list deleted

Failed calls are included. In Sentinel the `action` is matched in the `RequestParameters` text as `"action": "ARCHIVE"`, written so it gives the same result as on the field.

Not covered:

- **`UpdateThreatIntelSet`** pointing a threat list at a different or empty file, and `CreateThreatIntelSet` (adding threat intel is the normal direction).
- **`DeleteFilter`**, `ArchiveFindings` (findings archived by hand) and `UpdateFindingsFeedback`.
- **Changes to the list files themselves** in S3, which GuardDuty reads without a GuardDuty API call.

## Triage steps

1. **What was changed.** For a filter, read `requestParameters.findingCriteria`: which finding types, resources or IPs are now archived. A broad filter (all of a finding family, or a high severity range) is more suspicious than a narrow one. For an IP list, read `requestParameters.location` and get the file: which addresses are now trusted.
2. **Does it cover the attacker?** Compare the archived criteria or trusted IPs with current alerts and with `sourceIPAddress` values seen for suspicious activity in the account.
3. **Who and from where.** `userIdentity`, `sourceIPAddress`, `userAgent`. Compare with the people and pipelines that normally manage GuardDuty. Note `errorCode`.
4. **What else.** Search the same identity for other defense impairment in the same window (see the [GuardDuty disabled rule](aws_guardduty_disabled.md)), and for findings archived just before or after.
5. **Decide.** A recorded tuning change by the security team can be closed. Otherwise remove the filter or list, review findings archived since the change, and escalate.

## Known false positives

- **Suppression rules for accepted findings** (known scanners, expected port probes).
- **Trusted IP lists** for vulnerability scanners, VPN egress or partner ranges.

Tune by the security team's GuardDuty-management role together with a change window, never by caller alone.

## Related techniques

- **T1685 Disable or Modify Tools:** the technique itself.
- **T1685.002 Cloud Log** ([CloudTrail rules](aws_cloudtrail_logging_stopped_or_deleted.md)): often changed in the same window.
- **T1078.004 Cloud Accounts:** the access usually needed first.
