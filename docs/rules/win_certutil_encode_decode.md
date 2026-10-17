# Certutil Encoding or Decoding a Non-Certificate File

| | |
|---|---|
| **Rule** | [`rules/windows/stealth/win_certutil_encode_decode.yml`](../../rules/windows/stealth/win_certutil_encode_decode.yml) |
| **Rule ID** | `ff49547b-7901-4386-9392-0220bcbe341b` |
| **Level** | medium |
| **ATT&CK** | Stealth: T1140 Deobfuscate/Decode Files or Information, T1027 Obfuscated Files or Information |
| **Log source** | Process creation (Sysmon 1 / Security 4688) |

## Summary

`certutil.exe` Base64- or hex-encoded or decoded a file that isn't a certificate. Attackers bring payloads in as harmless-looking text and decode them on the host with certutil. APT29 day 2 decodes `blob` into `AppData\Roaming\Microsoft\kxwn.lock`, which is then run with rundll32. They also encode files for staging or exfiltration.

## What it detects

Process creation where `Image` ends with `\certutil.exe` and `CommandLine` contains ` -decode` or ` -encode`. Any dash style matches, and the hex variants are included.

Excluded: command lines that mention a certificate file (`.cer`, `.crt`, `.pem`, `.der`, `.p7b`, `.pfx`, `.p12`, `.req`, `.csr`, `.crl`), **unless** they also mention a DLL or script (`.dll`, `.ps1`, `.vbs`, `.js`, `.hta`, `.bat`, `.cmd`, `.scr`, `.sys`). That keeps certificate admin quiet while `-decode a.crt payload.dll` still fires.

Not covered:

- **`-decode <cert-named file> <name>.exe`.** `.exe` can't be in the override list, because every certutil command line contains `certutil.exe` itself. So a certificate-looking input decoded to an `.exe` is missed. A `.exe` payload without a certificate name (for example `-decode file.txt c:\file.exe`) is still caught.
- **Cert-named input decoded to a non-script extension** (for example `-decode payload.crt payload.lock`).
- **Renamed certutil** (see the renamed-binary rule) and other decoders (PowerShell `FromBase64String`, see the encoded-PowerShell rule).

## Triage steps

1. **What was decoded, and to where.** Read both file arguments. An output in `AppData`, `Temp`, `Users\Public` or `ProgramData`, with an executable, DLL, script or odd extension (`.lock`, `.dat`, `.tmp`), points to payload staging.
2. **Where the input came from.** Look for the file creation (Sysmon 11) of the encoded input shortly before, a download (the certutil-download rule, a browser, PowerShell), or an email attachment.
3. **What used the output.** Look for execution or loading of the decoded file within minutes: `rundll32 <file>,<export>` (the rundll32 rule), `regsvr32`, a service, a task, or direct execution.
4. **For `-encode`:** what was encoded and why. Encoding of archives, documents or credential stores (`.zip`, `.7z`, `.kdbx`, `ntds.dit`, `SAM`) suggests staging for exfiltration.
5. **Parent and user.** PowerShell, `cmd` from Office or script hosts, or a remote session (WMI, PsExec) are high-signal parents.
6. **Decide.** A known admin script encoding a config or licence blob can be tuned out by exact command line. Decoding into user-writable paths followed by execution should be escalated.

## Known false positives

- **Admins or scripts Base64-encoding non-certificate files** for transport (configuration blobs, licence files).
- **Certificate work using non-standard extensions** (for example `.b64` → `.txt` round-trips of certificate data).

Tune by exact command line and parent, not by `certutil.exe` or user.

## Related techniques

- **T1105 Ingress Tool Transfer:** the encoded payload is often fetched first, sometimes by certutil `-urlcache` (the certutil-download rule).
- **T1218.011 Rundll32:** decoded DLLs launched with rundll32, as in the APT29 day 2 chain.
- **T1036.003 Rename Legitimate Utilities:** renamed certutil copies used to avoid name-based rules.
- **T1560 Archive Collected Data:** archives encoded before exfiltration.
