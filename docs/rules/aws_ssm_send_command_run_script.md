# AWS SSM SendCommand Running a Shell or Script Document

| | |
|---|---|
| **Rule** | [`rules/aws/execution/aws_ssm_send_command_run_script.yml`](../../rules/aws/execution/aws_ssm_send_command_run_script.yml) |
| **Rule ID** | `dc5b6916-d571-4087-b60d-0cd251f14513` |
| **Level** | medium |
| **ATT&CK** | Execution: T1651 Cloud Administration Command |
| **Log source** | AWS CloudTrail (`ssm.amazonaws.com`) |

## Summary

Someone used Systems Manager Run Command to run arbitrary commands on one or more instances. The SSM agent runs them as root or SYSTEM, so anyone with `ssm:SendCommand` controls every managed instance without network access to it or credentials on it. Stratus Red Team's sample runs a shell script this way, the cloud version of remote execution over PsExec or WMI.

## What it detects

CloudTrail `eventSource` `ssm.amazonaws.com`, `eventName` `SendCommand`, and `requestParameters.documentName` containing one of these documents:

- `AWS-RunShellScript`
- `AWS-RunPowerShellScript`
- `AWS-RunRemoteScript`, which downloads a script from S3 or GitHub and runs it

Failed calls are included. Notes:

- The match is a plain `contains`, so the document named by its ARN (`arn:aws:ssm:<region>::document/AWS-RunShellScript`) also matches.
- CloudTrail writes the commands as `HIDDEN_DUE_TO_SECURITY_REASONS`, so the rule can't see them; triage step 2 says where to find them.
- `requestParameters.instanceIds` or `targets` (tags, resource groups) say where the commands ran.

Not covered:

- **Other documents:** AWS documents for patching, inventory and agent updates, and custom documents. An attacker who can create a document (`CreateDocument`) can wrap commands in one with an innocent name.
- **Session Manager** (`StartSession`): interactive shells, a different behaviour.
- **State Manager associations** (`CreateAssociation`) that run a document on a schedule.
- **Defender XDR:** no CloudTrail table ("unsupported", like the other AWS rules).

## Triage steps

1. **Who sent it, to which instances?** Check `userIdentity`, `errorCode`, and `instanceIds`/`targets`. A denied attempt is still an attempt, and a tag target can reach a whole fleet.
2. **What ran?** Look up the `commandId` from `responseElements` in SSM Run Command history (`ListCommands`/`GetCommandInvocation`) or in its S3/CloudWatch output, if configured. On the instance, check the SSM agent logs and the process tree under `ssm-document-worker` or `ssm-agent-worker`.
3. **Is this caller normally doing this?** Is it a known admin or pipeline role, from its usual `sourceIPAddress` and `userAgent`? New credentials, a console session from an unusual place, or an IAM user that never used SSM before are bad signs.
4. **What happened next?** On the instance: new users, keys, outbound connections, or credentials pulled from the instance metadata service. In CloudTrail: calls made with the instance role's credentials from outside AWS.
5. **Decide.** An expected deployment or admin task, with a matching change record, is benign: tune by caller and document. Otherwise isolate the targeted instances, revoke the caller's credentials and the instance role's sessions, and investigate the hosts.

## Known false positives

- **Ad hoc admin commands** through Run Command.
- **Deployment pipelines** that install software with `AWS-RunShellScript` or `AWS-RunRemoteScript`.

## Related techniques

- **T1059 Command and Scripting Interpreter:** what runs on the instance.
- **T1552.005 Cloud Instance Metadata API:** stealing the instance role's credentials once on the host.
- **T1021.007 Remote Services: Cloud Services:** Session Manager shells (`StartSession`), not covered here.
