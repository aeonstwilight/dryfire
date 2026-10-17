"""Convert every Sigma rule into Splunk SPL and Microsoft KQL.

Output goes to build/:
    build/spl/<rule>.spl              Splunk
    build/kql/sentinel/<rule>.kql     Microsoft Sentinel (SecurityEvent table)
    build/kql/defender/<rule>.kql     Microsoft Defender XDR (Device* tables)
    build/conversion_summary.md       One row per rule, one column per target

Exit code is 1 if any rule fails to convert, so CI goes red.

One exception: the Kusto pipelines only know tables for some log sources
(process creation, file, registry, network...). When a pipeline has no table
for a rule's log source, that rule/target pair is reported as "unsupported"
and does not fail the build. Any other error does.
"""

import argparse
import sys
from pathlib import Path

from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.pipelines.sysmon import sysmon_pipeline


def sentinel_security_log_pipeline():
    """Our own pipeline: Security-log rules -> SecurityEvent (see the YAML file)."""
    path = Path("pipelines/sentinel_security_log.yml")
    return ProcessingPipeline.from_yaml(path.read_text(encoding="utf-8"))


# Each target: which backend to use, which pipelines to apply (in order),
# and where to write the output. Pipelines map generic Sigma log sources and
# field names onto what each SIEM actually stores.
#
# Splunk: `sysmon` turns generic categories (process_creation, process_access...)
#   into Sysmon Event IDs; `splunk_windows` adds the source="WinEventLog:..." filter.
# Sentinel: our own pipelines/sentinel_security_log.yml first (Security-log
#   rules -> SecurityEvent), then `azure_monitor`, which maps process creation
#   to SecurityEvent and checks every field against the table.
# Defender: `microsoft_xdr` maps to DeviceProcessEvents and friends.
TARGETS = {
    "splunk": {
        "backend": SplunkBackend,
        "pipelines": [sysmon_pipeline, splunk_windows_pipeline],
        "out_dir": Path("build/spl"),
        "ext": ".spl",
    },
    "sentinel": {
        "backend": KustoBackend,
        "pipelines": [sentinel_security_log_pipeline, azure_monitor_pipeline],
        "out_dir": Path("build/kql/sentinel"),
        "ext": ".kql",
    },
    "defender": {
        "backend": KustoBackend,
        "pipelines": [microsoft_xdr_pipeline],
        "out_dir": Path("build/kql/defender"),
        "ext": ".kql",
    },
}

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
    return "ok", "\n\n".join(str(q) for q in queries) + "\n"


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

    failures = 0
    summary_rows = []
    for rule_path in rule_paths:
        row = [rule_path.stem]
        for name, target in TARGETS.items():
            status, text = convert_rule(rule_path, target)
            if status == "ok":
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
