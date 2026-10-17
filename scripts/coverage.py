"""Build an ATT&CK Navigator layer from the rules' ATT&CK tags.

Writes build/coverage/layer.json. Open it at
https://mitre-attack.github.io/attack-navigator/ ("Open Existing Layer").

Each technique a rule is tagged with gets a score equal to the number of rules
covering it, and a comment listing those rules. If a rule also has tactic tags
(e.g. attack.credential-access), the technique is marked under those tactics only.
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

OUTPUT = Path("build/coverage/layer.json")

# Navigator layer file format. Spec:
# https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md
# The ATT&CK version is left out so Navigator loads its latest.
LAYER_FORMAT_VERSION = "4.5"
NAVIGATOR_VERSION = "5.3.2"

# attack.t1003 or attack.t1003.001
TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
# attack.credential-access (letters, hyphens, underscores; no digits, so
# technique, group and software tags like t1003 or g0007 don't match)
TACTIC_TAG = re.compile(r"^attack\.([a-z][a-z_-]+)$")

# Rules with these statuses aren't counted as coverage.
SKIP_STATUSES = {"deprecated", "unsupported"}


def read_rule(path):
    """Return (title, status, techniques, tactics) for one rule file."""
    rule = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    techniques, tactics = [], []
    for tag in rule.get("tags") or []:
        tag = str(tag).lower()
        if m := TECHNIQUE_TAG.match(tag):
            techniques.append(m.group(1).upper())
        elif m := TACTIC_TAG.match(tag):
            # Navigator uses hyphens: credential-access, not credential_access.
            tactics.append(m.group(1).replace("_", "-"))
    return rule.get("title", path.stem), rule.get("status"), techniques, tactics


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules-dir", default="rules", type=Path)
    args = parser.parse_args()

    # (technique, tactic) -> list of rule titles. tactic is None when the
    # rule has no tactic tag, which shows the technique under every tactic.
    coverage = {}
    rule_count = 0
    for path in sorted(args.rules_dir.rglob("*.yml")):
        title, status, techniques, tactics = read_rule(path)
        if status in SKIP_STATUSES:
            continue
        if not techniques:
            print(f"WARN  {path}: no ATT&CK technique tags, not in coverage layer")
            continue
        rule_count += 1
        for technique in techniques:
            for tactic in tactics or [None]:
                coverage.setdefault((technique, tactic), []).append(title)

    techniques = []
    for (technique, tactic), titles in sorted(coverage.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        entry = {
            "techniqueID": technique,
            "score": len(titles),
            "comment": "; ".join(titles),
            "enabled": True,
        }
        if tactic:
            entry["tactic"] = tactic
        techniques.append(entry)

    max_score = max((t["score"] for t in techniques), default=1)
    layer = {
        "name": "dryfire coverage",
        "description": f"Techniques covered by {rule_count} Sigma rule(s). Score = number of rules.",
        "domain": "enterprise-attack",
        "versions": {"layer": LAYER_FORMAT_VERSION, "navigator": NAVIGATOR_VERSION},
        "filters": {"platforms": ["Windows"]},
        "sorting": 3,  # highest score first
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff"],
            "minValue": 0,
            # Navigator needs maxValue > minValue.
            "maxValue": max(max_score, 1),
        },
        "legendItems": [],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT}: {len(coverage)} technique/tactic entries from {rule_count} rule(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
