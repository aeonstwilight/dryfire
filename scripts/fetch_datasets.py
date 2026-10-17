"""Download the public datasets listed in tests/datasets.yml.

Files go to tests/data/external/ (gitignored). Each file's SHA-256 is checked
against the manifest, so a changed or tampered file fails instead of silently
changing test results. Files already present with the right hash are skipped.

Exit code is 1 if any download fails or any hash doesn't match.
"""

import hashlib
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

MANIFEST = Path("tests/datasets.yml")
DEST_DIR = Path("tests/data/external")


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url, dest):
    """Download url to dest via a temp file, so a failed download leaves nothing behind."""
    # Encode spaces etc. in the URL path (leaves already-encoded %20 alone).
    url = urllib.parse.quote(url, safe=":/%?=&")
    tmp = dest.with_name(dest.name + ".part")
    with urllib.request.urlopen(url, timeout=120) as response, open(tmp, "wb") as f:
        while chunk := response.read(1024 * 1024):
            f.write(chunk)
    tmp.replace(dest)


def main():
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8")) or {}
    entries = manifest.get("datasets") or []
    if not entries:
        print(f"No datasets listed in {MANIFEST}.")
        return 0

    failures = 0
    for entry in entries:
        url, expected = entry["url"], entry.get("sha256")
        dest = DEST_DIR / entry["path"]
        # Keep downloads inside DEST_DIR, whatever the manifest says.
        if not dest.resolve().is_relative_to(DEST_DIR.resolve()):
            print(f"FAIL  {entry['path']}: path must stay inside {DEST_DIR}/")
            failures += 1
            continue

        if dest.exists() and expected and sha256_of(dest) == expected:
            print(f"OK    {dest} (already downloaded)")
            continue

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            download(url, dest)
        except Exception as e:
            print(f"FAIL  {dest}: download failed: {e}")
            failures += 1
            continue

        actual = sha256_of(dest)
        if not expected:
            print(f"FAIL  {dest}: no sha256 in manifest. Downloaded file hashes to:\n"
                  f"      sha256: {actual}\n"
                  f"      Check the file, then add that line to its entry in {MANIFEST}.")
            failures += 1
        elif actual != expected:
            print(f"FAIL  {dest}: sha256 mismatch\n      expected {expected}\n      got      {actual}")
            dest.unlink()
            failures += 1
        else:
            print(f"OK    {dest}")

    if failures:
        print(f"{failures} dataset(s) failed.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
