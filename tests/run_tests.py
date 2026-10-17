"""Run every Sigma rule against its test case using Zircolite.

For each rule in rules/ this checks that:
  - tests/cases/<rule_filename>.yml exists and points at the rule
  - docs/rules/<rule_filename>.md (the triage note) exists
  - every positive sample produces at least `min_hits` hits
  - every negative sample produces 0 hits

Test case format (paths relative to the repo root):

    rule: rules/windows/credential_access/win_example.yml
    pipelines: [sysmon, windows-logsources]   # optional, this is the default
    positive:
      - file: tests/data/external/evtx-attack-samples/example.evtx
        min_hits: 1
    negative:
      - file: tests/data/samples/benign_example.evtx

`pipelines` are the pySigma pipelines Zircolite applies before matching.
The default suits Sysmon samples. For Security 4688 process-creation samples
use [windows-audit, windows-logsources].

Exit code is 1 if anything fails. Results are also written to build/tests/results.md.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

DEFAULT_PIPELINES = ["sysmon", "windows-logsources"]
RESULTS_FILE = Path("build/tests/results.md")


def count_hits(zircolite, rule_path, sample_path, pipelines):
    """Run Zircolite on one sample with one rule and return the number of matched events.

    Raises RuntimeError if Zircolite fails (bad sample, rule it can't convert, ...).
    """
    # Run in a temp folder: Zircolite writes its log file to the current directory.
    with tempfile.TemporaryDirectory() as tmp:
        out_file = Path(tmp) / "detections.json"
        cmd = [str(zircolite.resolve()), "--quiet",
               "--events", str(sample_path.resolve()),
               "--ruleset", str(rule_path.resolve()),
               "--outfile", str(out_file)]
        for pipeline in pipelines:
            cmd += ["--pipeline", pipeline]

        result = subprocess.run(cmd, cwd=tmp, capture_output=True, text=True)
        if result.returncode != 0 or not out_file.exists():
            output = (result.stdout + result.stderr).strip().splitlines()
            raise RuntimeError("Zircolite failed: " + " | ".join(output[-5:]))

        # Output is a list with one entry per rule that matched; each has a "count".
        detections = json.loads(out_file.read_text(encoding="utf-8"))
        return sum(d.get("count", 0) for d in detections)


def check_rule(rule_path, args):
    """Run all checks for one rule. Returns a list of (check, passed, detail)."""
    name = rule_path.stem
    results = []

    note = args.docs_dir / f"{name}.md"
    results.append(("triage note", note.exists(), str(note) if note.exists() else f"missing {note}"))

    case_path = args.cases_dir / f"{name}.yml"
    if not case_path.exists():
        results.append(("test case", False, f"missing {case_path}"))
        return results

    case = yaml.safe_load(case_path.read_text(encoding="utf-8")) or {}
    case_rule = Path(case.get("rule", ""))
    if case_rule.resolve() != rule_path.resolve():
        results.append(("test case", False, f"{case_path} has rule: {case_rule}, expected {rule_path}"))
        return results

    positives = case.get("positive") or []
    negatives = case.get("negative") or []
    if not positives or not negatives:
        results.append(("test case", False, f"{case_path} needs at least one positive and one negative sample"))
        return results

    pipelines = case.get("pipelines") or DEFAULT_PIPELINES
    samples = [(p["file"], int(p.get("min_hits", 1)), "positive") for p in positives]
    samples += [(n["file"] if isinstance(n, dict) else n, 0, "negative") for n in negatives]

    for file, min_hits, kind in samples:
        sample = Path(file)
        label = f"{kind}: {sample.name}"
        if not sample.exists():
            hint = " (run `make datasets`)" if "external" in sample.parts else ""
            results.append((label, False, f"sample not found: {sample}{hint}"))
            continue
        try:
            hits = count_hits(args.zircolite, rule_path, sample, pipelines)
        except RuntimeError as e:
            results.append((label, False, str(e)))
            continue
        if kind == "positive":
            results.append((label, hits >= min_hits, f"{hits} hit(s), expected >= {min_hits}"))
        else:
            results.append((label, hits == 0, f"{hits} hit(s), expected 0"))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules-dir", default="rules", type=Path)
    parser.add_argument("--cases-dir", default="tests/cases", type=Path)
    parser.add_argument("--docs-dir", default="docs/rules", type=Path)
    parser.add_argument("--zircolite", type=Path,
                        default=Path(os.environ.get("ZIRCOLITE", "tools/zircolite/Zircolite")),
                        help="path to the Zircolite binary (default: tools/zircolite/Zircolite or $ZIRCOLITE)")
    args = parser.parse_args()

    rule_paths = sorted(args.rules_dir.rglob("*.yml"))
    if not rule_paths:
        print(f"No rules found in {args.rules_dir}/, nothing to test.")
        return 0
    if not args.zircolite.exists():
        print(f"Zircolite not found at {args.zircolite}. Run `make zircolite` or pass --zircolite.")
        return 1

    failures = 0
    report = ["| Rule | Check | Result | Detail |", "|---|---|---|---|"]
    for rule_path in rule_paths:
        print(f"\n{rule_path}")
        for check, passed, detail in check_rule(rule_path, args):
            status = "PASS" if passed else "FAIL"
            failures += not passed
            print(f"  {status}  {check}: {detail}")
            report.append(f"| {rule_path.stem} | {check} | {status} | {detail} |")

    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_FILE.write_text("\n".join(report) + "\n", encoding="utf-8")

    print()
    if failures:
        print(f"{failures} check(s) failed across {len(rule_paths)} rule(s).")
        return 1
    print(f"All checks passed for {len(rule_paths)} rule(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
