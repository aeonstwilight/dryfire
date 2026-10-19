# Windows Password Spray From One Source

| | |
|---|---|
| **Rule** | [`rules/windows/credential_access/win_password_spray_from_one_source.yml`](../../rules/windows/credential_access/win_password_spray_from_one_source.yml) |
| **Rule ID** | `8b5fb25e-453f-4ce5-8aa2-5f8c9bf7746b` |
| **Level** | medium |
| **ATT&CK** | Credential Access: T1110.003 Password Spraying |
| **Log source** | Windows Security log (4625, 4771), usually on domain controllers and servers |

## Summary

One source address failed to log on as 10 or more different users within 30 minutes, with a wrong password or a user name that doesn't exist. That's the shape of a password spray: one or two common passwords tried across many accounts, slowly enough to stay under lockout thresholds. Misconfigured services and shared egress addresses produce the same shape, hence medium.

## What it detects

A Sigma correlation rule (`value_count`) over two base rules, in one file:

- **4625** with `SubStatus` `0xc000006a` (wrong password) or `0xc0000064` (no such user)
- **4771** with `Status` `0x18` (Kerberos pre-authentication failed), which covers Kerberos-based spraying such as kerbrute
- source addresses `-`, empty and loopback are left out (local logons)
- **correlation:** 10 or more distinct `TargetUserName` per `IpAddress` within 30 minutes

Engine notes:

- **Address spelling.** 4771 writes the address as `::ffff:<IPv4>`, 4625 as plain IPv4, so in Splunk (and Zircolite) NTLM and Kerberos failures from one host are counted separately. Elastic stores `source.ip` as an IP and drops the `::ffff:`, so there they're counted together.
- **Time windows.** Splunk and Elastic count in fixed 30-minute buckets. A spray split across a bucket boundary alerts in a sliding window but not there.
- **Sentinel and Defender:** pySigma-backend-kusto doesn't convert correlation rules, so both are declared unsupported.

Not covered:

- **Slow sprays** (fewer than 10 users per 30 minutes per address).
- **Sprays spread over many source addresses.**
- **Locked-out (`0xc0000234`) or disabled (`0xc0000072`, 4771 `0x12`) accounts**, which appear during a spray but aren't guesses.
- **Spraying against cloud identity providers** (Entra ID sign-in logs, ADFS), which don't write these events.

## Triage steps

1. **Who's the source.** Resolve `IpAddress`: a workstation, a server, a VPN or proxy pool, or an external address (through a published service). Check the `WorkstationName` in 4625 for the claimed client name.
2. **Which accounts.** List the `TargetUserName` values: alphabetical lists, `admin`/`test`/`svc` names or many non-existent users (`0xc0000064`) point to a spray; a fixed set of accounts that always fails from a server points to a stale-credential service.
3. **Did any succeed?** Search 4624 (and 4768/4769 for Kerberos) for the same source and the same accounts during and after the window. A success is the priority: treat that account as compromised.
4. **Lockouts.** 4740 events and `0xc0000234` failures from the same source show how far it got.
5. **What else from the source.** Other logons, process execution or network connections from that host around the time.
6. **Decide.** A known service or scanner can be closed and tuned by source. Otherwise block or isolate the source, reset any account that logged on successfully, and escalate.

## Known false positives

- **Misconfigured services or scripts** with stale credentials for many accounts.
- **Credentialed vulnerability scans** across many accounts.
- **Shared egress addresses** (NAT, proxy, VPN concentrator) where many users mistype passwords.

Tune by source address for known scanners and services, never by account.

## Related techniques

- **T1110.003 Password Spraying:** the technique itself.
- **T1110.001 Password Guessing:** many passwords against one account (the brute-force rule).
- **T1078.002 Domain Accounts:** what a successful spray gives the attacker.
