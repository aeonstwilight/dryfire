"""Run `sigma check` against a pinned ATT&CK version.

By default pySigma validates ATT&CK tags against MITRE's latest release, so a
new ATT&CK release could fail the lint step with no change in this repo. This
script downloads one fixed ATT&CK release (checked by SHA-256), tells pySigma
to use it, then runs the normal `sigma check`. Any arguments are passed
straight through to `sigma check`.

To move to a new ATT&CK release: update the three ATTACK_* values below
(the commit of the release tag, the file name, and its hash), then fix any
rule tags the new release invalidates.
"""

import hashlib
import sys
import urllib.request
from pathlib import Path

from sigma.cli.check import check
from sigma.data import mitre_attack

ATTACK_VERSION = "20.0"
# Commit that the attack-stix-data tag v20.0 points to.
ATTACK_COMMIT = "20664a889568dce884a1dac0ec7b12ae3a199f51"
ATTACK_SHA256 = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"{ATTACK_COMMIT}/enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
# tools/ is gitignored, so the 55 MB file is downloaded once and reused.
ATTACK_FILE = Path(f"tools/attack/enterprise-attack-{ATTACK_VERSION}.json")


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_attack_data():
    """Make sure the pinned ATT&CK file is on disk with the right hash."""
    if ATTACK_FILE.exists() and sha256_of(ATTACK_FILE) == ATTACK_SHA256:
        return
    print(f"Downloading ATT&CK v{ATTACK_VERSION} data...")
    ATTACK_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = ATTACK_FILE.with_name(ATTACK_FILE.name + ".part")
    with urllib.request.urlopen(ATTACK_URL, timeout=300) as response, open(tmp, "wb") as f:
        while chunk := response.read(1024 * 1024):
            f.write(chunk)
    actual = sha256_of(tmp)
    if actual != ATTACK_SHA256:
        tmp.unlink()
        sys.exit(f"ATT&CK data hash mismatch: expected {ATTACK_SHA256}, got {actual}")
    tmp.replace(ATTACK_FILE)


def main():
    get_attack_data()
    # Point pySigma's ATT&CK tag validator at the pinned local file.
    mitre_attack.set_url(str(ATTACK_FILE.resolve()))
    print(f"Validating ATT&CK tags against v{mitre_attack.mitre_attack_version}")
    # Hand over to sigma-cli's own `check` command with our arguments.
    check.main(args=sys.argv[1:], prog_name="sigma check")


if __name__ == "__main__":
    main()
