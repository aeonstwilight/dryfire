"""Check every rule's metadata and triage note against the repo conventions.

Run by `make lint` after `sigma check`. `sigma check` validates Sigma itself;
this script checks the things CLAUDE.md requires on top of that:

  - required fields are present and non-empty
  - id is a UUID, date is YYYY-MM-DD, status and level are Sigma values
  - at least one ATT&CK tactic tag and one technique tag
  - the file path is rules/<platform>/<tactic>/<prefix>_<name>.yml and the
    <tactic> folder is one of the rule's tactic tags
  - at least one reference points at a tagged technique on attack.mitre.org
  - the triage note has every template section, no leftover template
    placeholders, and the same Rule ID as the rule

Exit code is 1 if any rule fails.
"""

import argparse
import re
import sys
import uuid
from datetime import date
from pathlib import Path

import yaml

REQUIRED_FIELDS = ["id", "title", "status", "description", "author", "date", "tags",
                   "logsource", "detection", "falsepositives", "level", "references"]
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
# Platform folder -> required filename prefix.
PLATFORM_PREFIX = {"windows": "win", "aws": "aws"}

TECHNIQUE_TAG = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$")
TACTIC_TAG = re.compile(r"^attack\.([a-z][a-z_-]+)$")
TEMPLATE = Path("docs/rules/_template.md")


def template_sections_and_placeholders():
    """Read the triage-note template: its '## ' headings and its <placeholder> tokens."""
    text = TEMPLATE.read_text(encoding="utf-8")
    sections = re.findall(r"^## .+$", text, flags=re.M)
    placeholders = set(re.findall(r"<[^<>\n]+>", text))
    return sections, placeholders


def check_rule(path, rules_dir, docs_dir, sections, placeholders):
    """Return a list of problems for one rule (empty list = OK)."""
    problems = []
    rule = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    # Required fields
    for field in REQUIRED_FIELDS:
        if rule.get(field) in (None, "", [], {}):
            problems.append(f"missing or empty field: {field}")

    # id, date, status, level
    rule_id = str(rule.get("id", ""))
    try:
        if str(uuid.UUID(rule_id)) != rule_id:
            problems.append(f"id is not a lowercase canonical UUID: {rule_id}")
    except ValueError:
        problems.append(f"id is not a UUID: {rule_id}")
    # PyYAML turns 2026-10-17 into a date object; accept that or the plain string.
    rule_date = rule.get("date")
    if not (isinstance(rule_date, date) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(rule_date))):
        problems.append(f"date is not YYYY-MM-DD: {rule_date}")
    if rule.get("status") not in STATUSES:
        problems.append(f"status must be one of {sorted(STATUSES)}: {rule.get('status')}")
    if rule.get("level") not in LEVELS:
        problems.append(f"level must be one of {sorted(LEVELS)}: {rule.get('level')}")

    # ATT&CK tags
    tags = [str(t).lower() for t in rule.get("tags") or []]
    techniques = [m for t in tags if (m := TECHNIQUE_TAG.match(t))]
    tactics = [m.group(1) for t in tags if not TECHNIQUE_TAG.match(t) and (m := TACTIC_TAG.match(t))]
    if not tactics:
        problems.append("no ATT&CK tactic tag (attack.<tactic>)")
    if not techniques:
        problems.append("no ATT&CK technique tag (attack.tXXXX[.XXX])")

    # Path: rules/<platform>/<tactic>/<prefix>_<name>.yml
    parts = path.relative_to(rules_dir).parts
    if len(parts) != 3:
        problems.append(f"path must be {rules_dir}/<platform>/<tactic>/<file>.yml")
    else:
        platform, tactic_folder, filename = parts
        prefix = PLATFORM_PREFIX.get(platform)
        if prefix is None:
            problems.append(f"unknown platform folder '{platform}' (add it to PLATFORM_PREFIX)")
        elif not filename.startswith(prefix + "_"):
            problems.append(f"filename must start with '{prefix}_'")
        if tactic_folder.replace("_", "-") not in tactics:
            problems.append(f"tactic folder '{tactic_folder}' is not one of the rule's tactic tags {tactics}")

    # References: at least one ATT&CK URL for a tagged technique
    refs = [str(r) for r in rule.get("references") or []]
    technique_urls = []
    for m in techniques:
        tid = "T" + m.group(1) + ("/" + m.group(2) if m.group(2) else "")
        technique_urls.append(f"attack.mitre.org/techniques/{tid}")
    if techniques and not any(u in r for r in refs for u in technique_urls):
        problems.append("no reference to a tagged technique on attack.mitre.org")

    # Triage note
    note = docs_dir / f"{path.stem}.md"
    if not note.exists():
        problems.append(f"missing triage note {note}")
    else:
        text = note.read_text(encoding="utf-8")
        for section in sections:
            if not re.search("^" + re.escape(section) + r"\s*$", text, flags=re.M):
                problems.append(f"triage note missing section '{section}'")
        left_over = sorted(p for p in placeholders if p in text)
        if left_over:
            problems.append(f"triage note still has template placeholders: {', '.join(left_over)}")
        if f"`{rule_id}`" not in text:
            problems.append(f"triage note Rule ID doesn't match the rule id {rule_id}")

    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules-dir", default="rules", type=Path)
    parser.add_argument("--docs-dir", default="docs/rules", type=Path)
    args = parser.parse_args()

    sections, placeholders = template_sections_and_placeholders()
    rule_paths = sorted(args.rules_dir.rglob("*.yml"))
    failed = 0
    for path in rule_paths:
        problems = check_rule(path, args.rules_dir, args.docs_dir, sections, placeholders)
        if problems:
            failed += 1
            print(f"FAIL  {path}")
            for p in problems:
                print(f"      - {p}")
    if failed:
        print(f"{failed} of {len(rule_paths)} rule(s) failed metadata checks.")
        return 1
    print(f"Metadata checks passed for {len(rule_paths)} rule(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
