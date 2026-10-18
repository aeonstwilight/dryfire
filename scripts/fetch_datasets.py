"""Download the public datasets listed in tests/datasets.yml (or another manifest).

Files go to tests/data/external/ (gitignored). Each file's SHA-256 is checked
against the manifest, so a changed or tampered file fails instead of silently
changing test results. Files already present with the right hash are skipped.

Use --manifest to read a different list, e.g. tests/sweep_corpus.yml for the
noise sweep.

AWS CloudTrail files come in different shapes ({"Records": [...]} as AWS
writes them, one event per line, or zipped). Zircolite only reads one event
per line (JSON Lines), so an entry with a `jsonl:` path also gets a JSON Lines
copy written there after its hash check. The original is kept as downloaded.

Exit code is 1 if any download fails or any hash doesn't match.
"""

import argparse
import hashlib
import io
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
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


# GitHub answers 429 (Too Many Requests) when a CI runner downloads hundreds of
# files in a row; 5xx errors are usually short outages. Both are retried.
RETRY_STATUS = {429, 500, 502, 503, 504}
ATTEMPTS = 6


def download(url, dest):
    """Download url to dest via a temp file, so a failed download leaves nothing behind.

    Retries on rate limiting and server errors, waiting as long as the server's
    Retry-After header asks, or 5, 10, 20, 40, 80 seconds.
    """
    # Encode spaces etc. in the URL path (leaves already-encoded %20 alone).
    url = urllib.parse.quote(url, safe=":/%?=&")
    tmp = dest.with_name(dest.name + ".part")
    for attempt in range(1, ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(url, timeout=120) as response, open(tmp, "wb") as f:
                while chunk := response.read(1024 * 1024):
                    f.write(chunk)
            tmp.replace(dest)
            return
        except urllib.error.HTTPError as e:
            if e.code not in RETRY_STATUS or attempt == ATTEMPTS:
                raise
            retry_after = e.headers.get("Retry-After", "")
            wait = int(retry_after) if retry_after.isdigit() else 5 * 2 ** (attempt - 1)
            print(f"      HTTP {e.code}, retrying {dest.name} in {wait}s")
            time.sleep(wait)


def cloudtrail_records(path):
    """Return the CloudTrail events in a file, whatever its shape.

    Handles a zip (reads every .json file in it), {"Records": [...]},
    a plain JSON list, or one JSON event per line.
    """
    if zipfile.is_zipfile(path):
        records = []
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.endswith(".json"):
                    records += parse_cloudtrail_text(z.read(name).decode("utf-8"))
        return records
    return parse_cloudtrail_text(Path(path).read_text(encoding="utf-8"))


def parse_cloudtrail_text(text):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Not one JSON document: read it as one event per line.
        return [json.loads(line) for line in io.StringIO(text) if line.strip()]
    if isinstance(data, dict) and "Records" in data:
        return data["Records"]
    return data if isinstance(data, list) else [data]


def write_jsonl(source, dest):
    """Write the CloudTrail events in `source` to `dest`, one JSON event per line."""
    records = cloudtrail_records(source)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")
    return len(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", default=MANIFEST, type=Path)
    args = parser.parse_args()

    manifest = yaml.safe_load(args.manifest.read_text(encoding="utf-8")) or {}
    entries = manifest.get("datasets") or []
    if not entries:
        print(f"No datasets listed in {args.manifest}.")
        return 0

    failures = 0
    already_there = 0
    for entry in entries:
        url, expected = entry["url"], entry.get("sha256")
        dest = DEST_DIR / entry["path"]
        # Keep downloads inside DEST_DIR, whatever the manifest says.
        if not dest.resolve().is_relative_to(DEST_DIR.resolve()):
            print(f"FAIL  {entry['path']}: path must stay inside {DEST_DIR}/")
            failures += 1
            continue

        jsonl = DEST_DIR / entry["jsonl"] if entry.get("jsonl") else None
        if jsonl and not jsonl.resolve().is_relative_to(DEST_DIR.resolve()):
            print(f"FAIL  {entry['jsonl']}: path must stay inside {DEST_DIR}/")
            failures += 1
            continue

        if dest.exists() and expected and sha256_of(dest) == expected:
            already_there += 1
            if jsonl and not jsonl.exists():
                write_jsonl(dest, jsonl)
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
                  f"      Check the file, then add that line to its entry in {args.manifest}.")
            failures += 1
        elif actual != expected:
            print(f"FAIL  {dest}: sha256 mismatch\n      expected {expected}\n      got      {actual}")
            dest.unlink()
            failures += 1
        else:
            print(f"OK    {dest}")
            if jsonl:
                count = write_jsonl(dest, jsonl)
                print(f"      {count} event(s) -> {jsonl}")

    if already_there:
        print(f"OK    {already_there} file(s) already downloaded with the right hash")
    if failures:
        print(f"{failures} dataset(s) failed.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
