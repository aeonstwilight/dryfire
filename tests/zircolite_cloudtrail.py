"""Help Zircolite read AWS CloudTrail events with their full field names.

Zircolite flattens nested JSON to the last key only: `userIdentity.type`
becomes `type`, and `requestParameters.name` becomes `name`. Sigma rules for
CloudTrail use the full dotted names, so they would never match.

Zircolite's config file can rename a nested path to any column name. This
module writes a copy of Zircolite's default config with one extra mapping per
nested field found in the sample, each mapped to itself
(`userIdentity.type: userIdentity.type`). Lists are mapped at the list's own
path, because Zircolite keeps a list as one text column (match its contents
with `contains`).

Used by tests/run_tests.py, tests/run_sweep.py and tests/run_validate.py.
"""

import json
from pathlib import Path

import yaml


def jsonl_files(sample):
    """The JSON Lines files in a sample (a single .jsonl file or a folder of them)."""
    sample = Path(sample)
    if sample.is_dir():
        return sorted(sample.rglob("*.jsonl"))
    return [sample] if sample.suffix == ".jsonl" else []


def is_cloudtrail(sample):
    """True if the sample is JSON Lines whose first event looks like a CloudTrail record."""
    for path in jsonl_files(sample):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    event = json.loads(line)
                    return "eventVersion" in event and "eventSource" in event
    return False


def nested_paths(value, prefix=""):
    """Every dotted path below the top level: leaves and lists, not plain dicts."""
    paths = set()
    for key, inner in value.items():
        path = f"{prefix}{key}"
        if isinstance(inner, dict):
            paths |= nested_paths(inner, path + ".")
        elif prefix:  # top-level fields keep their name anyway
            paths.add(path)
    return paths


def write_config(sample, zircolite, out_dir):
    """Write a Zircolite config for a CloudTrail sample into out_dir and return its path.

    Returns None if the sample isn't CloudTrail, so Zircolite uses its default config.
    """
    if not is_cloudtrail(sample):
        return None
    paths = set()
    for path in jsonl_files(sample):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    paths |= nested_paths(json.loads(line))

    # Start from the config that ships with Zircolite, so everything else stays default.
    default = Path(zircolite).resolve().parent / "config" / "config.yaml"
    config = yaml.safe_load(default.read_text(encoding="utf-8"))
    config.setdefault("mappings", {})
    for path in sorted(paths):
        config["mappings"][path] = path

    out = Path(out_dir) / "zircolite_cloudtrail.yaml"
    out.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return out
