# AWS Security Group Ingress Opened to the Internet

| | |
|---|---|
| **Rule** | [`rules/aws/defense_impairment/aws_security_group_ingress_open_to_internet.yml`](../../rules/aws/defense_impairment/aws_security_group_ingress_open_to_internet.yml) |
| **Rule ID** | `2f141257-3d71-49f4-ba17-01178bff0f4c` |
| **Level** | medium |
| **ATT&CK** | Defense Impairment: T1686.001 Disable or Modify System Firewall: Cloud Firewall |
| **Log source** | AWS CloudTrail (`AuthorizeSecurityGroupIngress`, `ec2.amazonaws.com`) |

## Summary

An inbound security group rule was added that allows traffic from anywhere (`0.0.0.0/0` or `::/0`). Attackers open SSH, RDP or WinRM to reach instances directly, or open a database or management port to exfiltrate. Public web ports are opened legitimately all the time, so the rule is medium and triage ranks by port.

## What it detects

`AuthorizeSecurityGroupIngress` events where the new rule's source is `0.0.0.0/0` or `::/0`, on any port and protocol. Both request shapes are covered:

- **Rule list** (`requestParameters.ipPermissions.items`): any rule in the list, IPv4 (`ipRanges`) or IPv6 (`ipv6Ranges`)
- **Older flat parameters** (`requestParameters.cidrIp`), as the Stratus Red Team sample uses

Failed calls are included.

How each SIEM matches the rule list (see the pipeline files): Splunk looks in the list items' `...ipRanges.items{}.cidrIp` and `...ipv6Ranges.items{}.cidrIpv6` fields; Sentinel searches the `RequestParameters` JSON text.

Not covered:

- **Egress rules** (`AuthorizeSecurityGroupEgress`): allow-all outbound is the AWS default.
- **`ModifySecurityGroupRules`** (the newer API that edits existing rules) and **network ACL entries** (`CreateNetworkAclEntry` / `ReplaceNetworkAclEntry`).
- **Rules opened to a very wide but not universal range** (`0.0.0.0/1`, a large public block) or to another account's security group.
- **Which port in which rule:** the match is on the whole request, so in a multi-rule request the port open to the internet may not be the first one listed.

## Triage steps

1. **Which ports.** Read `requestParameters.ipPermissions.items` (or the flat `fromPort`/`toPort`/`ipProtocol`) and find the rule(s) with `0.0.0.0/0` or `::/0`. Rank:
   - **Highest:** all traffic (`ipProtocol: -1`), SSH 22, RDP 3389, WinRM 5985/5986, SMB 445
   - **High:** databases (1433, 3306, 5432, 6379, 9200, 27017), admin and management consoles (8000-8999, 8089, 9997 and similar)
   - **Lower:** 80 and 443 on a group that fronts a web server or load balancer
2. **Which group and what it protects.** `requestParameters.groupId`: find the instances, ENIs, load balancers or databases using it. An internet-open port on a group attached to nothing yet is less urgent than one on a running instance.
3. **Who did it, and how.** `userIdentity`, `sourceIPAddress`, `userAgent`. The EC2 console launch wizard (`console.ec2.amazonaws.com`) opening 22 or 80 for a new instance is common and usually careless rather than malicious; an SDK or CLI call from an unusual identity is not.
4. **Did it work?** `errorCode`; on success `responseElements` lists the new rule IDs.
5. **What followed.** Inbound connections in VPC flow logs to the opened port, new logins on the instance (SSH, RDP), and other changes by the same caller.
6. **Decide.** A ticketed public web listener can be closed (consider an allow-list of known public-facing groups). Otherwise revoke the rule and escalate, especially for admin and database ports.

## Known false positives

- **Public web servers or load balancers** opened on 80 or 443. In the test corpus, 60 port-80 rules added by the EC2 launch wizard fall here.
- **Short-lived test or lab environments.**

Tune by security group ID together with port (80/443 on known public-facing groups), never by caller alone.

## Related techniques

- **T1686.001 Cloud Firewall:** the technique itself.
- **T1021.004 SSH / T1021.001 Remote Desktop Protocol:** remote access through the opened port.
- **T1133 External Remote Services:** services exposed for persistent access.
