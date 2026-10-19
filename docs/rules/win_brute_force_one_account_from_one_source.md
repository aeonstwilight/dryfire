# Windows Brute Force Against One Account From One Source

| | |
|---|---|
| **Rule** | [`rules/windows/credential_access/win_brute_force_one_account_from_one_source.yml`](../../rules/windows/credential_access/win_brute_force_one_account_from_one_source.yml) |
| **Rule ID** | `d8e46973-3665-4f21-a28e-12d4ad52705f` |
| **Level** | medium |
| **ATT&CK** | Credential Access: T1110.001 Password Guessing |
| **Log source** | Windows Security log (4625, 4771), usually on domain controllers and servers |

## Summary

One source address failed 10 or more times with a wrong password for the same account within 30 minutes. That's password guessing against one account, or a device or service retrying an old password. The question that matters is whether a guess then worked, which is the first triage step.

## What it detects

A Sigma correlation rule (`event_count`) over two base rules, in one file:

- **4625** with `SubStatus` `0xc000006a` (wrong password)
- **4771** with `Status` `0x18` (Kerberos pre-authentication failed)
- source addresses `-`, empty and loopback are left out (local logons)
- **correlation:** 10 or more of these per `TargetUserName` and `IpAddress` within 30 minutes

**Why there's no "then succeeded" condition:** Sigma can express "10 failures, then a success" by chaining a count into a sequence, but neither the Splunk nor the ES|QL converter produces a working query for that. Checking for the success is the first triage step instead.

Engine notes:

- **Address spelling.** 4771 writes the address as `::ffff:<IPv4>`, so in Splunk (and Zircolite) NTLM and Kerberos failures for the same account from one host are counted separately. Elastic stores `source.ip` as an IP and counts them together.
- **Time windows.** Splunk and Elastic count in fixed 30-minute buckets. A burst split across a bucket boundary alerts in a sliding window but not there.
- **Sentinel and Defender:** pySigma-backend-kusto doesn't convert correlation rules, so both are declared unsupported.

Not covered:

- **Slow guessing** (fewer than 10 per 30 minutes).
- **Guessing from many addresses.**
- **Unknown user names** (`0xc0000064`).
- **Guessing against cloud identity providers** (Entra ID sign-in logs, ADFS).

## Triage steps

1. **Did it succeed?** Search 4624 (and 4768 for Kerberos) for the same `TargetUserName` from the same `IpAddress` during and after the burst. A success after many failures is the priority: treat the account as compromised.
2. **Who's the source.** Resolve `IpAddress` and check `WorkstationName`. Is it the account owner's own device, a server, or an external address through a published service?
3. **Password change or attack.** A recent password change for the account (4723/4724), with failures from the user's own devices, points to stale cached credentials. Failures for a privileged or service account from an unrelated host point to guessing.
4. **Lockout.** 4740 for the account shows whether the lockout policy stopped it; no lockout with many failures may mean the policy is weak or the account is exempt.
5. **What else from the source.** Other failures for different accounts (see the [spray rule](win_password_spray_from_one_source.md)), and any process or network activity on that host around the time.
6. **Decide.** A known stale-credential device or service can be closed once fixed. Otherwise block the source, reset the account if any logon succeeded, and escalate.

## Known false positives

- **Stale passwords** on services, scripts, scheduled tasks or mapped drives after a password change.
- **User devices** (phones, laptops) retrying cached credentials.
- **Shared accounts** behind one NAT or VPN address.

Tune by account and source pair for known stale-credential devices, never by account alone.

## Related techniques

- **T1110.001 Password Guessing:** the technique itself.
- **T1110.003 Password Spraying:** one password across many accounts (the spray rule).
- **T1078.002 Domain Accounts:** what a successful guess gives the attacker.
