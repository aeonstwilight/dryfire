"""Robustness check (M7 part B): do the rules survive attacker-style changes?

For every process-creation rule (and, with their own changes, every Sysmon 13 registry
rule and CloudTrail rule; see tests/variants.yml):
  1. run Zircolite on the rule's own positive samples and keep the events it
     matches (real events, from public datasets or our synthetic samples);
  2. for each variant in tests/variants.yml, change a copy of those events
     (upper-case the command line, quote the program, add carets, ...), keeping
     only the events the change applies to;
  3. run Zircolite again on the changed copies and count how many the rule
     still catches.

The result for each rule and variant is "caught / changed events": 3/3 means
the rule still catches every changed event, 0/3 that it misses them all, and
"-" that the variant didn't apply to any of the rule's events.

It writes build/robustness/summary.md (the table), build/robustness/misses.md
(the command lines a rule missed, for review) and build/robustness/results.json.
Then it compares every cell with tests/robustness_baseline.yml, the reviewed
results (owner decision, 2026-10-21), and exits 1 if any differs or a rule has
no baseline entry, as the noise sweep does. Without a baseline file it only
reports. The changed events are written to a temp folder and thrown away.
"""

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

import yaml

from run_tests import DEFAULT_PIPELINES, detection_hits, run_zircolite
from zircolite_cloudtrail import jsonl_files

VARIANTS_FILE = Path("tests/variants.yml")
BASELINE_FILE = Path("tests/robustness_baseline.yml")
OUT_DIR = Path("build/robustness")


# --- The changes ---------------------------------------------------------------
# Each takes one event (a dict of fields) and returns the changed copy, or None
# if the change doesn't apply (nothing to change). They never change the input.

def upper_case(event):
    cmd = event.get("CommandLine")
    if not cmd or cmd == cmd.upper():
        return None
    return {**event, "CommandLine": cmd.upper()}


def split_program(cmd):
    """Split a command line into (program, rest). The program may be quoted."""
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        if end == -1:
            return cmd, ""
        return cmd[:end + 1], cmd[end + 1:]
    space = cmd.find(" ")
    if space == -1:
        return cmd, ""
    return cmd[:space], cmd[space:]


def quote_program(event):
    cmd = event.get("CommandLine")
    if not cmd or cmd.startswith('"'):
        return None
    program, rest = split_program(cmd)
    return {**event, "CommandLine": f'"{program}"{rest}'}


def outside_quotes(text, change_char):
    """Rebuild text, passing each character outside double quotes through change_char."""
    out, quoted = [], False
    for ch in text:
        if ch == '"':
            quoted = not quoted
            out.append(ch)
        else:
            out.append(ch if quoted else change_char(ch))
    return "".join(out)


def double_spaces(event):
    cmd = event.get("CommandLine")
    if not cmd:
        return None
    program, rest = split_program(cmd)
    changed = program + outside_quotes(rest, lambda ch: "  " if ch == " " else ch)
    return None if changed == cmd else {**event, "CommandLine": changed}


def cmd_carets(event):
    cmd = event.get("CommandLine")
    if not cmd:
        return None
    m = re.search(r"\s/[ck]\s", cmd, re.IGNORECASE)
    if not m:
        return None
    head, tail = cmd[:m.end()], cmd[m.end():]
    changed = head + outside_quotes(tail, lambda ch: "^" + ch if ch.isalpha() else ch)
    return None if changed == cmd else {**event, "CommandLine": changed}


def swap_switch_prefix(event):
    cmd = event.get("CommandLine")
    if not cmd:
        return None
    program, rest = split_program(cmd)
    # A switch is a space followed by - or / and a letter: " -decode" <-> " /decode".
    changed = re.sub(r"(?<= )([-/])(?=[A-Za-z])", lambda m: "/" if m.group(1) == "-" else "-", rest)
    return None if changed == rest else {**event, "CommandLine": program + changed}


# PowerShell's -EncodedCommand switch in any of the spellings PowerShell accepts.
PS_ENCODED = re.compile(r"(?<=\s)[-/](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom"
                        r"|encodedcomm|encodedcomma|encodedcomman|encodedcommand)(?=\s)", re.IGNORECASE)


def ps_encoded(event, spelling):
    cmd = event.get("CommandLine")
    if not cmd or not PS_ENCODED.search(cmd):
        return None
    changed = PS_ENCODED.sub(spelling, cmd, count=1)
    return None if changed == cmd else {**event, "CommandLine": changed}


def ps_encoded_short(event):
    return ps_encoded(event, "-e")


def ps_encoded_long(event):
    return ps_encoded(event, "-EnCoDeDcOmMaNd")


def new_binary_path(event, new_name):
    """Image moved to C:\\Users\\Public\\<new_name>, and the program in CommandLine to match."""
    image = event.get("Image")
    if not image:
        return None
    old_name = image.split("\\")[-1]
    new_image = "C:\\Users\\Public\\" + (new_name or old_name)
    changed = {**event, "Image": new_image}
    cmd = event.get("CommandLine")
    if cmd:
        program, rest = split_program(cmd)
        if old_name.lower() in program.lower():
            quoted = program.startswith('"')
            changed["CommandLine"] = (f'"{new_image}"' if quoted else new_image) + rest
    return changed


def move_binary(event):
    return new_binary_path(event, None)


def rename_binary(event):
    return new_binary_path(event, "svcupdate.exe")


# --- Registry changes (Sysmon 13: TargetObject is the key and value, Details the data) ---

def changed_details(event, new):
    old = event.get("Details")
    return None if not old or new(old) == old else {**event, "Details": new(old)}


def reg_details_upper(event):
    return changed_details(event, str.upper)


def reg_program_quoted(event):
    """Quote the program at the start of the value data, as many installers write it."""
    def quote(text):
        m = re.match(r'^([^"]+?\.exe)(\s.*)?$', text, re.IGNORECASE)
        return f'"{m.group(1)}"{m.group(2) or ""}' if m else text
    return changed_details(event, quote)


def reg_comspec(event):
    """cmd.exe written as %ComSpec%, which a REG_EXPAND_SZ Run value expands when it runs."""
    return changed_details(event, lambda t: re.sub(
        r"(?:[a-z]:\\windows\\(?:system32|syswow64)\\)?cmd\.exe", "%ComSpec%", t,
        flags=re.IGNORECASE))


ENV_FOLDERS = [
    (r"[a-z]:\\users\\[^\\]+\\appdata\\roaming\\", "%APPDATA%\\"),
    (r"[a-z]:\\users\\[^\\]+\\appdata\\local\\temp\\", "%TEMP%\\"),
    (r"[a-z]:\\programdata\\", "%ProgramData%\\"),
    (r"[a-z]:\\users\\public\\", "%PUBLIC%\\"),
]


def reg_env_folders(event):
    """User-writable folders written as environment variables (%APPDATA%, %TEMP%, ...)."""
    def swap(text):
        for pattern, var in ENV_FOLDERS:
            text = re.sub(pattern, lambda m: var, text, flags=re.IGNORECASE)
        return text
    return changed_details(event, swap)


def reg_short_path(event):
    """ProgramData written as its 8.3 short name (PROGRA~3)."""
    return changed_details(event, lambda t: re.sub(r"\\programdata\\", lambda m: "\\PROGRA~3\\", t,
                                                   flags=re.IGNORECASE))


def changed_key(event, new):
    old = event.get("TargetObject")
    return None if not old or new(old) == old else {**event, "TargetObject": new(old)}


def reg_wow64_key(event):
    """The same Run key written by a 32-bit process (under WOW6432Node)."""
    return changed_key(event, lambda k: re.sub(r"(?i)^(HKLM\\SOFTWARE\\)(Microsoft\\Windows\\)",
                                               lambda m: m.group(1) + "WOW6432Node\\" + m.group(2), k))


def reg_runonce(event):
    """Run written as RunOnce (runs once at the next logon)."""
    return changed_key(event, lambda k: re.sub(r"(?i)\\CurrentVersion\\Run\\",
                                               lambda m: "\\CurrentVersion\\RunOnce\\", k))


# --- CloudTrail changes: the same API call made a different way --------------------

def ct_other_region(record):
    if not record.get("awsRegion") or record["awsRegion"] == "ap-southeast-3":
        return None
    return {**record, "awsRegion": "ap-southeast-3"}


def ct_assumed_role(record):
    ident = record.get("userIdentity") or {}
    if ident.get("type") not in ("IAMUser", "Root"):
        return None
    account = ident.get("accountId") or record.get("recipientAccountId") or "111122223333"
    new = {k: v for k, v in ident.items() if k != "userName"}
    new.update({
        "type": "AssumedRole", "principalId": "AROAEXAMPLEROLE00001:ops-session",
        "arn": f"arn:aws:sts::{account}:assumed-role/ops-role/ops-session",
        "sessionContext": {"sessionIssuer": {
            "type": "Role", "principalId": "AROAEXAMPLEROLE00001",
            "arn": f"arn:aws:iam::{account}:role/ops-role", "accountId": account,
            "userName": "ops-role"}},
    })
    return {**record, "userIdentity": new}


def ct_failed_call(record):
    if record.get("errorCode") or record.get("eventName") == "ConsoleLogin":
        return None  # console sign-in failures are recorded differently
    return {**record, "errorCode": "AccessDenied", "responseElements": None,
            "errorMessage": "User is not authorized to perform this operation"}


SDK_AGENT = "Boto3/1.35.0 md/Botocore#1.35.0 ua/2.0 os/linux#6.1 lang/python#3.12"


def ct_sdk_user_agent(record):
    if record.get("userAgent") == SDK_AGENT or record.get("eventName") == "ConsoleLogin":
        return None
    return {**record, "userAgent": SDK_AGENT}


def ct_via_vpc_endpoint(record):
    if record.get("vpcEndpointId"):
        return None
    return {**record, "sourceIPAddress": "10.0.12.34", "vpcEndpointId": "vpce-0example0000000"}


CHANGES = {f.__name__: f for f in [
    upper_case, quote_program, double_spaces, cmd_carets, swap_switch_prefix, ps_encoded_short,
    ps_encoded_long, move_binary, rename_binary,
    reg_details_upper, reg_program_quoted, reg_comspec, reg_env_folders, reg_short_path,
    reg_wow64_key, reg_runonce,
    ct_other_region, ct_assumed_role, ct_failed_call, ct_sdk_user_agent, ct_via_vpc_endpoint]}


# --- Running it ----------------------------------------------------------------

def rule_kind(logsource):
    """Which group of changes a rule gets: process_creation, registry or cloudtrail."""
    if logsource.get("category") == "process_creation":
        return "process_creation"
    if logsource.get("category") in ("registry_set", "registry_event"):
        return "registry"
    if logsource.get("service") == "cloudtrail":
        return "cloudtrail"
    return None


def checked_rules(rules_dir):
    """(path, kind) for every rule some change applies to, judged by its (first) document."""
    for path in sorted(rules_dir.rglob("*.yml")):
        doc = next(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        kind = rule_kind(doc.get("logsource") or {})
        if kind:
            yield path, kind


def matched_events(zircolite, rule, case):
    """The events the rule matches in its own positive samples (minus Zircolite's row_id)."""
    pipelines = case.get("pipelines", DEFAULT_PIPELINES)
    events = []
    for positive in case.get("positive") or []:
        for detection in run_zircolite(zircolite, rule, Path(positive["file"]), pipelines):
            for match in detection.get("matches", []):
                events.append({k: v for k, v in match.items() if k != "row_id"})
    return events, pipelines


def count_caught(zircolite, rule, events, pipelines, tmp):
    sample = Path(tmp) / "changed.json"  # JSON lines, like our synthetic samples
    sample.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    return sum(detection_hits(d) for d in run_zircolite(zircolite, rule, sample, pipelines))


def applies(variant, event):
    images = variant.get("only_image")
    if not images:
        return True
    image = str(event.get("Image", "")).lower()
    return any(image.endswith(i.lower()) for i in images)


def check_cloudtrail_rule(zircolite, rule, case, variants):
    """CloudTrail rules: change every record in the rule's positive samples and compare
    the rule's hits on the changed copy with its hits on the original. Zircolite's
    matches come back flattened, so the original nested records are changed instead.
    The result is "hits on the changed copy / hits on the original"."""
    files = [f for p in case.get("positive") or [] for f in jsonl_files(Path(p["file"]))]
    records = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            records += [json.loads(line) for line in fh if line.strip()]
    with tempfile.TemporaryDirectory() as tmp:
        original = count_records(zircolite, rule, records, tmp)
        results = {}
        for variant in variants:
            change = CHANGES[variant["change"]]
            changed = [change(r) for r in records]
            if not any(c is not None for c in changed):
                results[variant["id"]] = {"changed": 0, "caught": 0, "missed": []}
                continue
            mixed = [c if c is not None else r for c, r in zip(changed, records)]
            caught = count_records(zircolite, rule, mixed, tmp)
            missed = [] if caught >= original else [
                f"{caught} of {original} hits after the change"]
            results[variant["id"]] = {"changed": original, "caught": caught, "missed": missed}
    return original, results


def count_records(zircolite, rule, records, tmp):
    sample = Path(tmp) / "changed.jsonl"  # .jsonl + CloudTrail fields -> nested-name config
    sample.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return sum(detection_hits(d) for d in run_zircolite(zircolite, rule, sample, []))


def check_rule(zircolite, rule, case, variants):
    """Return {variant id: {"changed": n, "caught": n, "missed": [command lines]}} for one rule."""
    events, pipelines = matched_events(zircolite, rule, case)
    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        for variant in variants:
            change = CHANGES[variant["change"]]
            changed = [c for e in events if applies(variant, e) and (c := change(e)) is not None]
            if not changed:
                results[variant["id"]] = {"changed": 0, "caught": 0, "missed": []}
                continue
            caught = count_caught(zircolite, rule, changed, pipelines, tmp)
            missed = []
            if caught < len(changed):
                # Find which ones were missed, one event at a time (only when there are misses).
                for e in changed:
                    if count_caught(zircolite, rule, [e], pipelines, tmp) == 0:
                        missed.append(e.get("CommandLine") or e.get("Details") or e.get("Image") or "")
            results[variant["id"]] = {"changed": len(changed), "caught": caught, "missed": missed}
    return len(events), results


def cell(result):
    """One result as the report and the baseline write it: "caught/changed", or "-" if it didn't apply."""
    return "-" if result["changed"] == 0 else f"{result['caught']}/{result['changed']}"


def compare_with_baseline(all_results, proposed):
    """Return a list of differences from the baseline (empty if it matches). Changes marked
    `status: proposed` in variants.yml are reported but not checked until the owner reviews
    them; a rule that only proposed changes apply to needs no baseline entry yet."""
    baseline = yaml.safe_load(BASELINE_FILE.read_text(encoding="utf-8")) or {}
    problems = []
    for rule, (_, results) in all_results.items():
        checked = {vid: r for vid, r in results.items() if vid not in proposed}
        if not checked:
            continue
        if rule not in baseline:
            problems.append(f"{rule}: no baseline entry")
            continue
        for vid, result in checked.items():
            expected = str(baseline[rule].get(vid, "missing"))
            if cell(result) != expected:
                problems.append(f"{rule} / {vid}: got {cell(result)}, baseline {expected}")
    for rule in baseline:
        if rule not in all_results:
            problems.append(f"{rule}: in the baseline but no longer checked")
    return problems


KIND_TITLES = {"process_creation": "Process creation", "registry": "Registry (Sysmon 13)",
               "cloudtrail": "AWS CloudTrail (cells: hits after the change / hits before)"}


def write_reports(all_results, variants, kinds, proposed):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    lines = ["# Robustness check", "",
             "Each cell: events still caught / events the change applied to (`-`: didn't apply).",
             "Changes are described in [tests/variants.yml](../../tests/variants.yml); reviewed results are",
             "in [tests/robustness_baseline.yml](../../tests/robustness_baseline.yml). Changes marked",
             "(proposed) are reported only, until the owner reviews them.", ""]
    for kind, title in KIND_TITLES.items():
        rules = [r for r in all_results if kinds[r] == kind]
        if not rules:
            continue
        ids = [v["id"] for v in variants if v.get("applies_to", "process_creation") == kind]
        heads = [f"{i} (proposed)" if i in proposed else i for i in ids]
        lines += [f"## {title}", "", "| Rule | Events | " + " | ".join(heads) + " |",
                  "|---|---|" + "---|" * len(ids)]
        for rule in rules:
            n_events, results = all_results[rule]
            cells = []
            for vid in ids:
                r = results[vid]
                text = cell(r)
                cells.append(f"**{text}**" if r["caught"] < r["changed"] else text)
            lines.append(f"| {rule} | {n_events} | " + " | ".join(cells) + " |")
        lines.append("")
    (OUT_DIR / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    misses = ["# Robustness check: missed events", ""]
    for rule, (_, results) in all_results.items():
        for vid in results:
            for cmd in results[vid]["missed"]:
                misses.append(f"- **{rule}** / `{vid}`: `{cmd[:300]}`")
    if len(misses) == 2:
        misses.append("No misses.")
    (OUT_DIR / "misses.md").write_text("\n".join(misses) + "\n", encoding="utf-8")

    (OUT_DIR / "results.json").write_text(json.dumps(
        {rule: {vid: {k: r[k] for k in ("changed", "caught")} for vid, r in results.items()}
         for rule, (_, results) in all_results.items()}, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rules-dir", default="rules", type=Path)
    parser.add_argument("--cases-dir", default="tests/cases", type=Path)
    parser.add_argument("--zircolite", type=Path, required=True)
    args = parser.parse_args()

    variants = yaml.safe_load(VARIANTS_FILE.read_text(encoding="utf-8"))["variants"]
    unknown = [v["change"] for v in variants if v["change"] not in CHANGES]
    if unknown:
        sys.exit(f"{VARIANTS_FILE}: unknown change(s): {', '.join(unknown)}")

    proposed = {v["id"] for v in variants if v.get("status") == "proposed"}
    all_results, kinds = {}, {}
    for rule, kind in checked_rules(args.rules_dir):
        case = yaml.safe_load((args.cases_dir / f"{rule.stem}.yml").read_text(encoding="utf-8"))
        mine = [v for v in variants if v.get("applies_to", "process_creation") == kind]
        if not mine:
            continue
        check = check_cloudtrail_rule if kind == "cloudtrail" else check_rule
        try:
            all_results[rule.stem] = check(args.zircolite, rule, case, mine)
        except RuntimeError as e:
            sys.exit(f"{rule}: {e}")
        kinds[rule.stem] = kind
        n_events, results = all_results[rule.stem]
        short = ", ".join(f"{vid} {r['caught']}/{r['changed']}" for vid, r in results.items() if r["changed"])
        print(f"{rule.stem}: {n_events} event(s); {short}")

    write_reports(all_results, variants, kinds, proposed)
    print(f"\nReports written to {OUT_DIR}/")
    if not BASELINE_FILE.exists():
        print(f"No {BASELINE_FILE}: report only.")
        return
    problems = compare_with_baseline(all_results, proposed)
    for problem in problems:
        print(f"FAIL  {problem}")
    if problems:
        sys.exit(f"{len(problems)} robustness result(s) differ from {BASELINE_FILE}. "
                 "Review build/robustness/ and update the baseline only if the change is intended.")
    print(f"Robustness results match {BASELINE_FILE}.")


if __name__ == "__main__":
    main()
