# Certutil Downloading From a URL

| | |
|---|---|
| **Rule** | [`rules/windows/command_and_control/win_certutil_download.yml`](../../rules/windows/command_and_control/win_certutil_download.yml) |
| **Rule ID** | `5ca93264-7d64-4e46-bef8-a556c4cdd42f` |
| **Level** | high |
| **ATT&CK** | Command and Control: T1105 Ingress Tool Transfer |
| **Log source** | Process creation (Sysmon 1 / Security 4688) |

## Summary

`certutil.exe` was used to fetch something from a URL. Certutil is a signed Windows binary that's present everywhere and can download arbitrary files through its URL cache. That makes it a common way to pull a second-stage payload onto a host without bringing a download tool.

## What it detects

Process creation where all three are true:

- `Image` ends with `\certutil.exe`
- `CommandLine` contains ` -urlcache` or ` -verifyctl`. Any dash style matches: `-`, `/`, and the Unicode dashes –, — and ―.
- `CommandLine` contains `http://`, `https://` or `ftp://`

Requiring a URL keeps cache administration out: `certutil -urlcache` (list) and `certutil -urlcache * delete` (clear) don't download anything. The rule looks at certutil's own process, not its `cmd.exe` parent, so `cmd` escaping such as `h^ttp` is already stripped by the time certutil starts.

Not covered:

- **Renamed certutil** (for example, copied to `%TEMP%\tcm.tmp`). Matching is on `Image` only, because Sentinel's `SecurityEvent` has no `OriginalFileName` column. Renamed system utilities are a candidate for their own rule.
- **Encode and decode** (`-encode`, `-decode`, `-decodehex`; T1140). These often follow a download but are a separate behaviour with their own false positives (certificate admin). They're a candidate for a follow-up rule.
- **Downloads via a UNC path** or other schemes without a URL, and other download LOLBins (`bitsadmin`, `curl.exe`, PowerShell cradles).

## Triage steps

1. **Read the URL and destination.** Check where it downloaded from (raw IP, paste site, file-sharing service, newly registered domain) and where it saved the file (`Users\Public`, `Temp`, `ProgramData`, a web root).
2. **Check the parent chain.** Look at what launched certutil: `cmd` from an Office app, a script host, a webshell (`w3wp.exe`), a scheduled task or a service. Then check the user and integrity level.
3. **Check the file.** Look for Sysmon 11 (file created) for the destination path and hash the file. Certutil also leaves a copy in the user's or SYSTEM's `INetCache\…\CryptnetUrlCache` folders, which is useful if the destination was deleted.
4. **Look at what came next.** Check for a follow-up `certutil -decode` (Base64-wrapped payload), execution of the downloaded file, `rundll32`/`regsvr32` loading it, or a new service or task referencing it.
5. **Check the network side.** In proxy, DNS or firewall logs, look for the URL's host at the same time, and other hosts contacting it.
6. **Decide.** A PKI admin checking CRL/AIA retrieval against your own PKI URLs, from an admin workstation, is benign. Downloads of scripts, executables or DLLs from external hosts should be escalated.

## Known false positives

- **PKI administrators** testing CRL or AIA retrieval with `-urlcache` against internal certificate URLs.
- **Rare legacy scripts** that use certutil as a downloader because nothing else was available.

Tune by the exact URL host (your PKI distribution points) together with the parent process. Don't tune by user alone.

## Related techniques

- **T1140 Deobfuscate/Decode Files or Information:** `certutil -decode` on a Base64-encoded download.
- **T1036.003 Rename Legitimate Utilities:** certutil copied and renamed to dodge name-based detections.
- **T1218 System Binary Proxy Execution:** the wider family of signed Windows binaries abused for execution and transfer.
- **T1197 BITS Jobs:** `bitsadmin` is the other common built-in downloader.
- **T1059.003 Windows Command Shell:** certutil downloads are usually launched from `cmd /c`.
