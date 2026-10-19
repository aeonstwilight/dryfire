# AWS Network ACL Inbound Rule Opened to the Internet

| | |
|---|---|
| **Rule** | [`rules/aws/defense_impairment/aws_network_acl_ingress_open_to_internet.yml`](../../rules/aws/defense_impairment/aws_network_acl_ingress_open_to_internet.yml) |
| **Rule ID** | `adf32fdf-41db-42e3-a5ad-ebfd690496ff` |
| **Level** | medium |
| **ATT&CK** | Defense Impairment: T1686.001 Cloud Firewall |
| **Log source** | AWS CloudTrail (EC2 network ACL calls) |

## Summary

A network ACL entry now allows inbound traffic from anywhere (`0.0.0.0/0` or `::/0`). Network ACLs filter at the subnet edge, so this removes a layer of filtering for every instance in the subnets the ACL is associated with; only security groups remain. Public subnets do this on purpose, hence medium.

## What it detects

- `CreateNetworkAclEntry` or `ReplaceNetworkAclEntry` on `ec2.amazonaws.com`
- `ruleAction` `allow`, inbound (`egress` false), from `cidrBlock` `0.0.0.0/0` or `ipv6CidrBlock` `::/0`
- any protocol and port range

Failed calls are included.

Engine notes:

- **Sentinel and Elastic** search the request text (`RequestParameters`, `aws.cloudtrail.request_parameters`).
- `egress` is matched as `(^|[:=]\s*)false`, which matches the field value, Sentinel's JSON (`"egress": false`) and Elastic's map text (`egress=false`). It's the only boolean in these requests.

Not covered:

- **Outbound** allow-all entries: normal, and the default on every network ACL.
- **Wide but not universal ranges** (for example `0.0.0.0/1`).
- **Changing which ACL a subnet uses** (`ReplaceNetworkAclAssociation`), for example to a permissive one.
- **Deleting a deny entry** (`DeleteNetworkAclEntry`), which can open traffic that an allow entry with a higher number already permits.

## Triage steps

1. **What's open.** Read `requestParameters`: `aclProtocol` (`-1` is all traffic) and `portRange`. All traffic, or admin ports (22, 3389, 5985/5986), rank highest; 80/443 on a public subnet are usually expected.
2. **Does it take effect?** Entries are evaluated in `ruleNumber` order. A lower-numbered deny for the same traffic overrides it; check the ACL's current entries (`DescribeNetworkAcls`). Also check which subnets use this ACL.
3. **What sits behind it.** The instances in those subnets, and whether their security groups also allow the traffic (see the [security group rule](aws_security_group_ingress_open_to_internet.md)): the ACL and the security group together decide what's reachable.
4. **Who and from where.** `userIdentity`, `sourceIPAddress`, `userAgent`; note `errorCode`. Compare with the network team's usual roles and tooling.
5. **What else.** Search the same identity for security group changes, new instances, or other defense impairment in the same window.
6. **Decide.** A planned change for a public subnet can be closed. Otherwise remove or narrow the entry and escalate, especially for all traffic or admin ports.

## Known false positives

- **Public subnets** for load balancers or web servers, where the ACL allows inbound traffic and security groups do the filtering.
- **Infrastructure-as-code** recreating an ACL's intended entries.

Tune by ACL ID or subnet together with the deploying role, never by caller alone.

## Related techniques

- **T1686.001 Cloud Firewall:** the technique itself.
- **T1190 Exploit Public-Facing Application:** what an opened subnet invites.
- **T1021 Remote Services:** admin ports opened for direct remote access.
