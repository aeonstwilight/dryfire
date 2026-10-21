"""Convert every Sigma rule into Splunk SPL, Microsoft KQL and Elastic ES|QL.

Output goes to build/:
    build/spl/<rule>.spl              Splunk
    build/kql/sentinel/<rule>.kql     Microsoft Sentinel (SecurityEvent, AWSCloudTrail)
    build/kql/defender/<rule>.kql     Microsoft Defender XDR (Device* tables)
    build/elastic/<rule>.esql         Elastic ES|QL (ECS field names, integration data streams)
    build/conversion_summary.md       One row per rule, one column per target

Exit code is 1 if any rule fails to convert, so CI goes red.

One exception: the Kusto pipelines only know tables for some log sources
(process creation, file, registry, network...). When a pipeline has no table
for a rule's log source, that rule/target pair is reported as "unsupported"
and does not fail the build. Any other error does.

Declared exceptions: pipelines/unsupported_targets.yml lists rule/target pairs
that are known not to convert, each with a reason (for example a field the
target table doesn't have). Those are reported as "unsupported (declared)"
instead of failing. A declared pair that converts fine, or a rule name in that
file that doesn't exist, fails the build so the list stays accurate.
"""

import argparse
import re
import sys
from pathlib import Path

import yaml

from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.elasticsearch import ecs_windows
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.pipelines.sysmon import sysmon_pipeline

# Our ES|QL backend: the Elastic package's, with case-insensitive strings and
# regexes rewritten for Lucene (see the docstring in scripts/esql_backend.py).
from esql_backend import DryfireESQLBackend


def load_pipeline(path):
    """Load one of our own pipelines from pipelines/ (see the comments in each YAML file)."""
    return ProcessingPipeline.from_yaml(Path(path).read_text(encoding="utf-8"))


def sentinel_security_log_pipeline():
    """Security-log rules -> SecurityEvent."""
    return load_pipeline("pipelines/sentinel_security_log.yml")


def sentinel_cloudtrail_pipeline():
    """AWS CloudTrail rules -> AWSCloudTrail, with CloudTrail fields renamed to its columns."""
    return load_pipeline("pipelines/sentinel_cloudtrail.yml")


def splunk_cloudtrail_pipeline():
    """AWS CloudTrail rules -> sourcetype="aws:cloudtrail"."""
    return load_pipeline("pipelines/splunk_cloudtrail.yml")


def elastic_windows_raw_fields_pipeline():
    """Windows Security fields kept as winlog.event_data.<name> (runs before ecs_windows)."""
    return load_pipeline("pipelines/elastic_windows_raw_fields.yml")


def elastic_windows_pipeline():
    """Windows rules -> plain ECS fields, Elastic integration data streams, allowed fields only."""
    return load_pipeline("pipelines/elastic_windows.yml")


def elastic_cloudtrail_pipeline():
    """AWS CloudTrail rules -> Elastic AWS integration field names, allowed fields only."""
    return load_pipeline("pipelines/elastic_cloudtrail.yml")


# A CloudTrail field name as written in a rule (eventName, requestParameters.x):
# it has a capital letter, which none of the Elastic AWS integration's field
# names do. String values are lower-cased by our backend, so after removing
# the quoted values any capital letter left is an unmapped field.
QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')
RAW_CLOUDTRAIL_FIELD = re.compile(r"[A-Za-z_][\w.]*[A-Z][\w.]*")


def elastic_unmapped_fields(rule_path, query):
    """Fields left unmapped in an Elastic CloudTrail query, e.g. those a correlation
    counts or groups by: pipelines check only the fields in detections."""
    if "/aws/" not in rule_path.as_posix():
        return []
    return sorted(set(RAW_CLOUDTRAIL_FIELD.findall(QUOTED.sub("", query))))


# Each target: which backend to use, which pipelines to apply (in order),
# and where to write the output. Pipelines map generic Sigma log sources and
# field names onto what each SIEM actually stores.
#
# Splunk: `sysmon` turns generic categories (process_creation, process_access...)
#   into Sysmon Event IDs; `splunk_windows` adds the source="WinEventLog:..." filter;
#   our pipelines/splunk_cloudtrail.yml adds sourcetype="aws:cloudtrail" for AWS rules.
# Sentinel: our own pipelines first (Security-log rules -> SecurityEvent, AWS
#   CloudTrail rules -> AWSCloudTrail), then `azure_monitor`, which maps process
#   creation to SecurityEvent and checks every field against the table.
# Defender: `microsoft_xdr` maps to DeviceProcessEvents and friends.
# Elastic: `sysmon` as for Splunk, pipelines/elastic_windows_raw_fields.yml
#   (fields that stay under winlog.event_data), then the Elastic package's
#   `ecs_windows` (ECS field names), then ours: pipelines/elastic_windows.yml and
#   pipelines/elastic_cloudtrail.yml (data streams, field names, allowed fields).
TARGETS = {
    "splunk": {
        "backend": SplunkBackend,
        "pipelines": [sysmon_pipeline, splunk_windows_pipeline, splunk_cloudtrail_pipeline],
        "out_dir": Path("build/spl"),
        "ext": ".spl",
    },
    "sentinel": {
        "backend": KustoBackend,
        "pipelines": [sentinel_security_log_pipeline, sentinel_cloudtrail_pipeline, azure_monitor_pipeline],
        "out_dir": Path("build/kql/sentinel"),
        "ext": ".kql",
    },
    "defender": {
        "backend": KustoBackend,
        "pipelines": [microsoft_xdr_pipeline],
        "out_dir": Path("build/kql/defender"),
        "ext": ".kql",
    },
    "elastic": {
        "backend": DryfireESQLBackend,
        "pipelines": [sysmon_pipeline, elastic_windows_raw_fields_pipeline, ecs_windows,
                      elastic_windows_pipeline, elastic_cloudtrail_pipeline],
        "out_dir": Path("build/elastic"),
        "ext": ".esql",
        "check": elastic_unmapped_fields,
    },
}

# Reviewed exceptions: rule name -> target -> reason.
DECLARED_UNSUPPORTED = Path("pipelines/unsupported_targets.yml")

# Error text the Kusto pipelines raise when they have no table for a log source.
NO_TABLE_ERROR = "Unable to determine table name"


def build_backend(target):
    """Chain the target's pipelines together and hand them to its backend."""
    pipeline = None
    for make_pipeline in target["pipelines"]:
        pipeline = make_pipeline() if pipeline is None else pipeline + make_pipeline()
    return target["backend"](processing_pipeline=pipeline)


def convert_rule(rule_path, target):
    """Convert one rule for one target.

    Returns (status, text): status is "ok", "unsupported" or "error";
    text is the query for "ok", or the error message otherwise.
    """
    try:
        rules = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
        # A fresh backend per rule keeps each conversion independent.
        queries = build_backend(target).convert(rules)
    except Exception as e:  # any pySigma error: bad YAML, unknown field, ...
        message = str(e).strip()
        if NO_TABLE_ERROR in message:
            return "unsupported", "no table mapping for this log source"
        return "error", message.splitlines()[0]

    if not queries:
        return "error", "backend returned no query"
    text = "\n\n".join(str(q) for q in queries) + "\n"
    unmapped = target.get("check", lambda path, query: [])(rule_path, text)
    if unmapped:
        return "error", "field(s) with no mapping for this target: " + ", ".join(unmapped)
    return "ok", text


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules-dir", default="rules", type=Path)
    args = parser.parse_args()

    rule_paths = sorted(args.rules_dir.rglob("*.yml"))
    if not rule_paths:
        print(f"No rules found in {args.rules_dir}/, nothing to convert.")
        return 0

    for target in TARGETS.values():
        target["out_dir"].mkdir(parents=True, exist_ok=True)

    declared = {}
    if DECLARED_UNSUPPORTED.exists():
        declared = yaml.safe_load(DECLARED_UNSUPPORTED.read_text(encoding="utf-8")) or {}

    failures = 0
    # Every rule named in the exceptions file must exist.
    for name in sorted(set(declared) - {p.stem for p in rule_paths}):
        print(f"FAIL  {DECLARED_UNSUPPORTED}: no rule named {name}")
        failures += 1

    summary_rows = []
    for rule_path in rule_paths:
        row = [rule_path.stem]
        for name, target in TARGETS.items():
            status, text = convert_rule(rule_path, target)
            reason = (declared.get(rule_path.stem) or {}).get(name)
            if reason and status == "ok":
                print(f"FAIL  {rule_path} -> {name}: declared unsupported in {DECLARED_UNSUPPORTED} "
                      "but it converts; remove the entry")
                row.append("FAILED")
                failures += 1
            elif reason:
                print(f"SKIP  {rule_path} -> {name}: declared unsupported: {reason}")
                row.append("unsupported (declared)")
            elif status == "ok":
                out_file = target["out_dir"] / (rule_path.stem + target["ext"])
                out_file.write_text(text, encoding="utf-8")
                row.append("ok")
            elif status == "unsupported":
                print(f"SKIP  {rule_path} -> {name}: {text}")
                row.append("unsupported")
            else:
                print(f"FAIL  {rule_path} -> {name}: {text}")
                row.append("FAILED")
                failures += 1
        summary_rows.append(row)

    # Markdown summary, published with the build artifact.
    header = ["Rule"] + list(TARGETS)
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(row) + " |" for row in summary_rows]
    summary = "\n".join(lines) + "\n"
    Path("build/conversion_summary.md").write_text(summary, encoding="utf-8")
    print(summary)

    if failures:
        print(f"{failures} conversion(s) failed.")
        return 1
    print(f"Converted {len(rule_paths)} rule(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
