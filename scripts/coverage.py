"""Build an ATT&CK Navigator layer from the rules' ATT&CK tags.

Writes build/coverage/layer.json. Open it at
https://mitre-attack.github.io/attack-navigator/ ("Open Existing Layer").

Each technique a rule is tagged with gets a score equal to the number of rules
covering it, and a comment listing those rules.

Which tactic column a technique shows under: the rule's tactic tags, but only
the ones that technique actually belongs to in ATT&CK. (A rule tagged
execution + stealth with T1059.001 and T1027.010 puts T1059.001 under
Execution and T1027.010 under Stealth, not both under both.) The ATT&CK data
is the same pinned version lint.py uses.
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml
from sigma.data import mitre_attack

# lint.py sits in the same folder and owns the pinned ATT&CK download.
from lint import ATTACK_FILE, get_attack_data

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

    # Technique -> its tactics in the pinned ATT&CK version, e.g. "T1059.001" -> ["execution"]
    get_attack_data()
    mitre_attack.set_url(str(ATTACK_FILE.resolve()))
    attack_tactics = mitre_attack.mitre_attack_techniques_tactics_mapping

    # (technique, tactic) -> list of rule titles. tactic is None when no tag
    # pins it down, which shows the technique under every tactic it has.
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
            if technique not in attack_tactics:
                print(f"WARN  {path}: {technique} is not in ATT&CK v{mitre_attack.mitre_attack_version}")
            # Keep only the rule's tactics that this technique really belongs to.
            matching = [t for t in tactics if t in attack_tactics.get(technique, [])]
            if tactics and not matching:
                print(f"WARN  {path}: none of the rule's tactic tags apply to {technique}; "
                      "showing it under all its tactics")
            for tactic in matching or [None]:
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
