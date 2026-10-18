"""Noise sweep: run every rule against a large, mostly-normal corpus.

The unit tests (tests/run_tests.py) prove each rule fires on its own attack
samples and stays quiet on a few hand-picked benign events. The sweep asks the
other question: what else does each rule fire on? It runs all rules over every
source listed in tests/sweep_corpus.yml (the whole EVTX-ATTACK-SAMPLES set and
the OTRF APT29 evaluation days) and reports every hit.

Hits from a file that is one of the rule's own positive test samples are
labelled "own sample" so the review can focus on the rest.

Output (in build/sweep/):
    summary.md         hit counts per rule and source
    hits/<rule>.md     every hit outside the rule's own samples, with key fields
    counts.json        the raw counts

Baseline: if tests/sweep_baseline.yml exists, each rule's count per source must
match it exactly, or the sweep fails (exit 1). Without a baseline the sweep is
report-only and always exits 0 (unless Zircolite itself fails).
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

import yaml

CORPUS_MANIFEST = Path("tests/sweep_corpus.yml")
BASELINE = Path("tests/sweep_baseline.yml")
EXTERNAL = Path("tests/data/external")
OUT_DIR = Path("build/sweep")
DEFAULT_PIPELINES = ["sysmon", "windows-logsources"]

# Fields shown for each hit in the report, in this order, when present.
KEY_FIELDS = ["SystemTime", "UtcTime", "Computer", "Hostname", "EventID", "User",
              "ParentImage", "Image", "CommandLine",
              "SourceImage", "TargetImage", "GrantedAccess",
              "PipeName", "ServiceName", "ImagePath", "TaskName",
              "TargetUserName", "TargetSid", "MemberSid", "SubjectUserName"]


def load_rules(rules_dir, cases_dir):
    """Return a list of dicts: path, id, title, pipelines, own sample file names."""
    rules = []
    for path in sorted(rules_dir.rglob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        case_path = cases_dir / f"{path.stem}.yml"
        case = yaml.safe_load(case_path.read_text(encoding="utf-8")) if case_path.exists() else {}
        case = case or {}
        own = {Path(p["file"]).name for p in case.get("positive") or []}
        rules.append({"path": path, "name": path.stem, "id": str(rule.get("id")),
                      "title": rule.get("title", path.stem),
                      "pipelines": tuple(case.get("pipelines") or DEFAULT_PIPELINES),
                      "own": own})
    return rules


def run_zircolite(zircolite, source_path, rule_paths, pipelines):
    """Run Zircolite once over one source with several rules. Returns its detections list."""
    with tempfile.TemporaryDirectory() as tmp:
        out_file = Path(tmp) / "detections.json"
        cmd = [str(zircolite.resolve()), "--quiet", "--events", str(source_path.resolve()),
               "--outfile", str(out_file), "--ruleset"] + [str(p.resolve()) for p in rule_paths]
        for pipeline in pipelines:
            cmd += ["--pipeline", pipeline]
        result = subprocess.run(cmd, cwd=tmp, capture_output=True, text=True)
        if result.returncode != 0 or not out_file.exists():
            output = (result.stdout + result.stderr).strip().splitlines()
            raise RuntimeError(f"Zircolite failed on {source_path}: " + " | ".join(output[-5:]))
        return json.loads(out_file.read_text(encoding="utf-8"))


def describe(match):
    """One hit as a short markdown block of the key fields that are present."""
    lines = []
    for field in KEY_FIELDS:
        value = match.get(field)
        if value not in (None, "", "-"):
            text = str(value).replace("\n", " ")
            if len(text) > 400:
                text = text[:400] + " …"
            lines.append(f"  - `{field}`: `{text}`")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules-dir", default="rules", type=Path)
    parser.add_argument("--cases-dir", default="tests/cases", type=Path)
    parser.add_argument("--zircolite", type=Path,
                        default=Path(os.environ.get("ZIRCOLITE", "tools/zircolite/Zircolite")))
    args = parser.parse_args()

    rules = load_rules(args.rules_dir, args.cases_dir)
    if not rules:
        print(f"No rules found in {args.rules_dir}/, nothing to sweep.")
        return 0
    sources = (yaml.safe_load(CORPUS_MANIFEST.read_text(encoding="utf-8")) or {}).get("sources") or []
    by_id = {r["id"]: r for r in rules}

    # Rules that need the same pipelines run together, one Zircolite run per source.
    groups = defaultdict(list)
    for r in rules:
        groups[r["pipelines"]].append(r)

    # counts[rule][source] = {"own": n, "other": n}; hits[rule] = [(source, file, match)]
    counts = {r["name"]: {s["name"]: {"own": 0, "other": 0} for s in sources} for r in rules}
    hits = defaultdict(list)
    for source in sources:
        source_path = EXTERNAL / source["path"]
        if not source_path.exists():
            print(f"Sweep source missing: {source_path} (run `make sweep-datasets`)")
            return 1
        for pipelines, group in groups.items():
            print(f"Sweeping {source['name']} with {len(group)} rule(s), pipelines {list(pipelines)}")
            detections = run_zircolite(args.zircolite, source_path, [r["path"] for r in group], pipelines)
            for d in detections:
                rule = by_id.get(str(d.get("id")))
                if rule is None:
                    continue
                for m in d.get("matches", []):
                    file = Path(str(m.get("OriginalLogfile", ""))).name
                    kind = "own" if file in rule["own"] else "other"
                    counts[rule["name"]][source["name"]][kind] += 1
                    if kind == "other":
                        hits[rule["name"]].append((source["name"], file, m))

    # Reports
    (OUT_DIR / "hits").mkdir(parents=True, exist_ok=True)
    header = "| Rule | " + " | ".join(s["name"] for s in sources) + " |"
    lines = ["# Noise sweep", "",
             "Hits per source as `other` (+ `own` = hits in the rule's own positive test samples).", "",
             header, "|" + "---|" * (len(sources) + 1)]
    for r in rules:
        cells = []
        for s in sources:
            c = counts[r["name"]][s["name"]]
            cells.append(f"{c['other']}" + (f" (+{c['own']} own)" if c["own"] else ""))
        lines.append(f"| [{r['name']}](hits/{r['name']}.md) | " + " | ".join(cells) + " |")
    (OUT_DIR / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT_DIR / "counts.json").write_text(json.dumps(counts, indent=2) + "\n", encoding="utf-8")
    for r in rules:
        out = [f"# {r['title']}", "", f"Hits outside the rule's own test samples: {len(hits[r['name']])}", ""]
        for source, file, m in hits[r["name"]]:
            out += [f"- **{source}** / `{file}`", describe(m), ""]
        (OUT_DIR / "hits" / f"{r['name']}.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    print("\n".join(lines[4:]))
    print(f"\nReports written to {OUT_DIR}/")

    # Baseline check
    if not BASELINE.exists():
        print(f"No {BASELINE} yet: report only.")
        return 0
    baseline = yaml.safe_load(BASELINE.read_text(encoding="utf-8")) or {}
    failures = 0
    for r in rules:
        for s in sources:
            got = counts[r["name"]][s["name"]]["own"] + counts[r["name"]][s["name"]]["other"]
            want = (baseline.get(r["name"]) or {}).get(s["name"])
            if want is None:
                print(f"FAIL  {r['name']} / {s['name']}: no baseline entry (got {got})")
                failures += 1
            elif got != want:
                print(f"FAIL  {r['name']} / {s['name']}: {got} hit(s), baseline {want}")
                failures += 1
    if failures:
        print(f"{failures} sweep count(s) differ from {BASELINE}. "
              "Review build/sweep/ and update the baseline only if the change is intended.")
        return 1
    print(f"Sweep matches {BASELINE}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
