"""Read a rule file, including one that holds a Sigma correlation rule.

Most rule files hold one Sigma rule. A correlation rule file (for example "many
distinct secrets read by one identity in 10 minutes") holds two or more YAML
documents separated by `---`:

  1. the base rule(s): which events count (logsource and detection)
  2. the correlation rule, last: how they're counted (type, group-by, timespan,
     threshold), plus the metadata of the detection as a whole (id, title,
     level, tags, references, ...)

The correlation rule is what fires, so its metadata is the rule's metadata.
`load_rule` returns it with the base rule's `logsource` and `detection` added,
so scripts that read one rule per file (metadata checks, coverage, sweep) work
the same for both kinds.

Used by scripts/check_metadata.py, scripts/coverage.py and the test scripts.
"""

import yaml


def load_documents(path):
    """All non-empty YAML documents in the file, in order."""
    with open(path, encoding="utf-8") as f:
        return [doc for doc in yaml.safe_load_all(f) if doc]


def load_rule(path):
    """The rule's metadata as one dict (see the module docstring)."""
    docs = load_documents(path)
    if not docs:
        return {}
    if len(docs) == 1:
        return docs[0]
    rule = dict(docs[-1])
    base = docs[0]
    rule.setdefault("logsource", base.get("logsource"))
    rule.setdefault("detection", base.get("detection"))
    return rule


def correlation_group_by(path):
    """The correlation's group-by fields, or None if the file is a plain rule."""
    rule = load_rule(path)
    correlation = rule.get("correlation")
    if not correlation:
        return None
    return list(correlation.get("group-by") or [])
