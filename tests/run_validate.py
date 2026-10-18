"""Run the converted SPL and KQL queries on real query engines and compare with Zircolite.

`make test` proves the Sigma logic with Zircolite. This script proves the
converted queries in build/ (from `make convert`) actually run on Splunk and on
Kusto, and find the same events. For every rule, target and test sample:

  1. Zircolite counts the rule's hits on the sample (the same count as `make test`).
  2. The sample's events are loaded into the engine (see "How events are loaded").
  3. The converted query runs on those events and its hit count is compared.

A check fails if the query errors, its count differs from Zircolite's, or no
events from a positive sample could be loaded for that target. A negative
sample with no events for a target (for example a System-log sample against a
Security-log query) is reported as N/A.
Targets where the rule doesn't convert ("unsupported") are skipped.

Engines (start them with `scripts/engines.sh up`):
  - Splunk Enterprise container: SPL from build/spl/
  - Kusto emulator container: KQL from build/kql/sentinel/ and build/kql/defender/
    (the table a query reads is the first word of the query)

How events are loaded:
  - Splunk: every event as JSON (sourcetype _json) through the HTTP Event
    Collector, with `source` set from the event's Channel the way the
    splunk_windows pipeline expects (e.g. WinEventLog:Security) and EventCode
    added as a copy of EventID. Each sample gets its own `dryfire_file` value,
    and the query is limited to it.
  - Sentinel (SecurityEvent table): Security-channel events go in as they are,
    one column per field (fields with no matching column are dropped).
    Security 4688 events are skipped so the count stays comparable with
    Zircolite's Sysmon-based process-creation tests; instead each Sysmon 1
    event is added as a 4688-style row (Image -> NewProcessName, ParentImage ->
    ParentProcessName, CommandLine -> CommandLine). For 4698, TaskContent is
    wrapped in an EventData XML string, which is where SecurityEvent keeps it.
  - Defender (DeviceProcessEvents table): each Sysmon 1 event becomes one row
    (Image -> FolderPath, CommandLine -> ProcessCommandLine, ParentImage ->
    InitiatingProcessFolderPath, OriginalFileName ->
    ProcessVersionInfoOriginalFileName, and the file names split from the paths).

  - AWS CloudTrail: Splunk gets the original nested records with sourcetype
    aws:cloudtrail (fields extracted with their dotted names, list items with
    {}). The Kusto emulator gets an AWSCloudTrail row per record, using the
    same field-to-column mapping as the Sentinel conversion
    (pipelines/sentinel_cloudtrail.yml); requestParameters, responseElements
    and the other nested objects go in as JSON text, as Sentinel stores them.

  - CloudTrail events get Splunk's _time from their eventTime (as with the AWS
    add-on), so time-bucketed queries see the events' own times.

Correlation rules (e.g. many distinct secrets read by one identity) are
counted as the number of distinct groups over the threshold on every engine:
Zircolite's alerts are grouped by their group-by values (run_tests.py), and
the Splunk query's rows are counted by the rule's group-by fields. Splunk
buckets time in fixed windows (`bin _time`) where Zircolite slides them, so
the test samples keep each burst inside one clock-aligned bucket.

The table schemas (column names and types) come from pySigma-backend-kusto, the
same lists the build uses to reject fields that don't exist in a table.

This proves the queries run and match the Sigma logic on these loaded events.
It doesn't prove that real Sentinel or Defender data looks exactly like them.

Results: build/validate/results.md. Exit code 1 if anything fails.
"""

import argparse
import base64
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

import yaml
from sigma.pipelines.azuremonitor.tables import AZURE_MONITOR_TABLES
from sigma.pipelines.microsoftxdr.tables import MICROSOFT_XDR_TABLES

# Reuse the Zircolite runner from the unit tests so counts are computed the same way.
sys.path.insert(0, str(Path(__file__).parent))
from run_tests import DEFAULT_PIPELINES, count_hits  # noqa: E402
from zircolite_cloudtrail import is_cloudtrail, jsonl_files  # noqa: E402
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from rule_file import correlation_group_by  # noqa: E402

RESULTS_FILE = Path("build/validate/results.md")
ENV_FILE = Path("build/validate/engines.env")

SPLUNK_API = "https://localhost:8089"
SPLUNK_HEC = "https://localhost:8088"
SPLUNK_INDEX = "dryfire"
KUSTO_URL = "http://localhost:8080"
KUSTO_DB = "NetDefaultDB"

# Where each target's converted queries are. For KQL, the table a query reads
# is the first word of the query.
TARGETS = {
    "splunk": {"dir": Path("build/spl"), "ext": ".spl"},
    "sentinel": {"dir": Path("build/kql/sentinel"), "ext": ".kql"},
    "defender": {"dir": Path("build/kql/defender"), "ext": ".kql"},
}

# Column name -> Kusto type, from the backend's copy of Microsoft's schema.
SCHEMAS = {
    "SecurityEvent": {c: v["data_type"].lower() for c, v in AZURE_MONITOR_TABLES["SecurityEvent"].items()},
    "DeviceProcessEvents": {c: v["data_type"].lower() for c, v in MICROSOFT_XDR_TABLES["DeviceProcessEvents"].items()},
    "AWSCloudTrail": {c: v["data_type"].lower() for c, v in AZURE_MONITOR_TABLES["AWSCloudTrail"].items()},
}

# CloudTrail field -> AWSCloudTrail column: the same mapping the Sentinel
# conversion uses (pipelines/sentinel_cloudtrail.yml), so loaded rows and
# converted queries agree on which column holds what.
CLOUDTRAIL_PIPELINE = Path("pipelines/sentinel_cloudtrail.yml")
CLOUDTRAIL_COLUMNS = next(
    t["mapping"] for t in yaml.safe_load(CLOUDTRAIL_PIPELINE.read_text(encoding="utf-8"))["transformations"]
    if t["type"] == "field_name_mapping")
# CloudTrail objects that AWSCloudTrail keeps as JSON text in one column.
CLOUDTRAIL_JSON_COLUMNS = {
    "requestParameters": "RequestParameters",
    "responseElements": "ResponseElements",
    "additionalEventData": "AdditionalEventData",
    "resources": "Resources",
    "serviceEventDetails": "ServiceEventDetails",
}

# Event Channel -> Splunk source, as written by the splunk_windows pipeline.
# Keys are lowercase: some OTRF datasets record the channel in lowercase
# ("security"), and Zircolite matches it case-insensitively too.
SPLUNK_SOURCES = {
    "security": "WinEventLog:Security",
    "system": "WinEventLog:System",
    "microsoft-windows-sysmon/operational": "WinEventLog:Microsoft-Windows-Sysmon/Operational",
}

SECURITY = "security"
SYSMON = "microsoft-windows-sysmon/operational"

# Splunk runs with a self-signed certificate inside the local container.
NO_VERIFY = ssl.create_default_context()
NO_VERIFY.check_hostname = False
NO_VERIFY.verify_mode = ssl.CERT_NONE


# --- Reading events -----------------------------------------------------------

def read_events(zircolite, sample, rule_path):
    """The sample's events: CloudTrail as the original nested records, Windows as
    Zircolite's flattened events."""
    if is_cloudtrail(sample):
        events = []
        for path in jsonl_files(sample):
            with open(path, encoding="utf-8") as f:
                events += [json.loads(line) for line in f if line.strip()]
        return events
    return flattened_events(zircolite, sample, rule_path)


def flattened_events(zircolite, sample, rule_path):
    """Return the sample's events as Zircolite sees them (flat dicts).

    Zircolite's --keepflat writes the flattened events to a JSON-lines file.
    --no-event-filter keeps every event, not just the ones the rule could match.
    """
    with tempfile.TemporaryDirectory() as tmp:
        cmd = [str(zircolite.resolve()), "--quiet", "--no-event-filter", "--keepflat",
               "--events", str(sample.resolve()), "--ruleset", str(rule_path.resolve()),
               "--outfile", str(Path(tmp) / "detections.json")]
        result = subprocess.run(cmd, cwd=tmp, capture_output=True, text=True)
        flat = list(Path(tmp).glob("flattened_events_*.json"))
        if result.returncode != 0 or not flat:
            raise RuntimeError("Zircolite --keepflat failed: " + (result.stdout + result.stderr).strip()[-300:])
        return [json.loads(line) for line in flat[0].read_text(encoding="utf-8").splitlines() if line.strip()]


def channel(event):
    """The event's channel in lowercase ("" if missing)."""
    return str(event.get("Channel") or "").lower()


def basename(path):
    """File name from a Windows path ("C:\\a\\b.exe" -> "b.exe")."""
    return path.replace("/", "\\").rsplit("\\", 1)[-1] if path else path


# --- Event -> engine mappings --------------------------------------------------

def cloudtrail_epoch(event_time):
    """A CloudTrail eventTime (2026-10-18T17:00:01Z) as Unix seconds."""
    return datetime.fromisoformat(event_time.replace("Z", "+00:00")).timestamp()


def is_cloudtrail_event(event):
    return "eventVersion" in event and "eventSource" in event


def to_splunk(event):
    """Return (source, sourcetype, event) for Splunk, or None if it's not a log we query.

    CloudTrail events keep their nested JSON and get sourcetype aws:cloudtrail,
    as the Splunk Add-on for AWS gives them; Splunk then extracts fields with
    the same dotted names (userIdentity.type).
    """
    if is_cloudtrail_event(event):
        return "dryfire:cloudtrail", "aws:cloudtrail", event
    source = SPLUNK_SOURCES.get(channel(event))
    if source is None:
        return None
    event = dict(event)
    if "EventID" in event:
        event["EventCode"] = event["EventID"]
    return source, "_json", event


def to_security_event(event):
    """Return a SecurityEvent row, or None if the event doesn't belong in that table."""
    event_id = str(event.get("EventID"))
    if channel(event) == SYSMON and event_id == "1":
        return {
            "EventID": 4688,
            "Computer": event.get("Computer"),
            "NewProcessName": event.get("Image"),
            "CommandLine": event.get("CommandLine"),
            "ParentProcessName": event.get("ParentImage"),
            "Process": basename(event.get("Image")),
        }
    if channel(event) != SECURITY or event_id == "4688":
        return None
    row = {k: v for k, v in event.items() if k in SCHEMAS["SecurityEvent"]}
    if "TaskContent" in event:
        row["EventData"] = ('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                            f'<Data Name="TaskName">{event.get("TaskName", "")}</Data>'
                            f'<Data Name="TaskContent">{event["TaskContent"]}</Data></EventData>')
    return row


def nested_value(event, path):
    """The value at a dotted path ("userIdentity.type"), or None."""
    value = event
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def to_aws_cloudtrail(event):
    """Return an AWSCloudTrail row for a CloudTrail record, otherwise None."""
    if not is_cloudtrail_event(event):
        return None
    row = {column: nested_value(event, path) for path, column in CLOUDTRAIL_COLUMNS.items()}
    for field, column in CLOUDTRAIL_JSON_COLUMNS.items():
        if event.get(field) is not None:
            row[column] = json.dumps(event[field])
    row["TimeGenerated"] = event.get("eventTime")
    return row


def to_device_process_event(event):
    """Return a DeviceProcessEvents row for a Sysmon 1 event, otherwise None."""
    if channel(event) != SYSMON or str(event.get("EventID")) != "1":
        return None
    return {
        "ActionType": "ProcessCreated",
        "DeviceName": event.get("Computer"),
        "FileName": basename(event.get("Image")),
        "FolderPath": event.get("Image"),
        "ProcessCommandLine": event.get("CommandLine"),
        "ProcessVersionInfoOriginalFileName": event.get("OriginalFileName"),
        "InitiatingProcessFileName": basename(event.get("ParentImage")),
        "InitiatingProcessFolderPath": event.get("ParentImage"),
        "InitiatingProcessCommandLine": event.get("ParentCommandLine"),
    }


def typed_row(row, table):
    """Drop empty values and convert each value to its column's type."""
    out = {}
    for column, value in row.items():
        if value is None or value == "":
            continue
        kind = SCHEMAS[table].get(column)
        if kind is None:
            continue
        try:
            if kind in ("int", "long"):
                value = int(str(value), 0) if str(value).lower().startswith("0x") else int(value)
            elif kind == "real":
                value = float(value)
            elif kind == "bool":
                value = str(value).lower() in ("1", "true")
            elif kind == "string":
                value = str(value)
            elif kind == "datetime":
                value = str(value)  # Kusto reads ISO 8601 text
        except ValueError:
            continue  # a value that doesn't fit the column stays empty, as in a real table
        out[column] = value
    return out


# Which loader builds rows for each Kusto table.
TABLE_MAPPERS = {
    "SecurityEvent": to_security_event,
    "DeviceProcessEvents": to_device_process_event,
    "AWSCloudTrail": to_aws_cloudtrail,
}


# --- Splunk -------------------------------------------------------------------

class Splunk:
    def __init__(self, password, hec_token):
        self.auth = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()
        self.hec_token = hec_token
        self.loaded = {}  # sample path -> (dryfire_file value, number of events)
        # The index keeps events between runs, so every run labels its events
        # with its own random prefix and only searches for those.
        self.run_id = uuid.uuid4().hex[:8]

    def _post(self, url, data, headers):
        request = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(request, context=NO_VERIFY, timeout=300) as response:
            return response.read().decode("utf-8")

    def setup(self):
        try:
            self._post(f"{SPLUNK_API}/services/data/indexes", urllib.parse.urlencode({"name": SPLUNK_INDEX}).encode(),
                       {"Authorization": self.auth})
        except urllib.error.HTTPError as e:
            if e.code != 409:  # 409: the index already exists
                raise

    def count(self, search):
        """Run a search and return the `count` from `| stats count`."""
        body = urllib.parse.urlencode({"search": search + "\n| stats count", "output_mode": "json"}).encode()
        text = self._post(f"{SPLUNK_API}/services/search/jobs/export", body, {"Authorization": self.auth})
        for line in text.splitlines():
            message = json.loads(line)
            for m in message.get("messages", []):
                if m.get("type") in ("ERROR", "FATAL"):
                    raise RuntimeError(f"Splunk: {m.get('text')}")
            if "result" in message:
                return int(message["result"].get("count", 0))
        raise RuntimeError(f"Splunk returned no result: {text[:300]}")

    def load(self, sample, events):
        """Send a sample's events once and wait until Splunk has indexed all of them."""
        if sample in self.loaded:
            return self.loaded[sample]  # (file id, number of events)
        file_id = f"{self.run_id}-{len(self.loaded)}"
        batch = []
        for event in events:
            mapped = to_splunk(event)
            if mapped:
                source, sourcetype, data = mapped
                data = {"dryfire_file": file_id, **data}
                hec_event = {"index": SPLUNK_INDEX, "source": source, "sourcetype": sourcetype, "event": data}
                if sourcetype == "aws:cloudtrail":
                    # Splunk's _time is the record's eventTime, as with the AWS add-on;
                    # correlation rules bucket events by _time.
                    hec_event["time"] = cloudtrail_epoch(data["eventTime"])
                batch.append(json.dumps(hec_event))
        for i in range(0, len(batch), 500):
            self._post(f"{SPLUNK_HEC}/services/collector/event", "".join(batch[i:i + 500]).encode(),
                       {"Authorization": f"Splunk {self.hec_token}"})
        # HEC returns before indexing finishes; wait until every event is searchable.
        for _ in range(60):
            if self.count(f'search index={SPLUNK_INDEX} dryfire_file="{file_id}"') >= len(batch):
                break
            time.sleep(2)
        else:
            raise RuntimeError(f"Splunk indexed fewer than {len(batch)} events for {sample.name}")
        self.loaded[sample] = (file_id, len(batch))
        return self.loaded[sample]

    def run(self, query, sample, events, group_by=None):
        """Return (hit count, number of events loaded for this sample).

        For a correlation rule (group_by set) the query returns one row per
        time bucket and group over the threshold; the hit count is the number
        of distinct groups, the same as run_tests.py counts with Zircolite.
        """
        file_id, loaded = self.load(sample, events)
        search = f'search index={SPLUNK_INDEX} dryfire_file="{file_id}" {query.strip()}'
        if group_by:
            search += "\n| stats count by " + " ".join(group_by)
        return self.count(search), loaded


# --- Kusto --------------------------------------------------------------------

class Kusto:
    def _call(self, kind, csl):
        body = json.dumps({"db": KUSTO_DB, "csl": csl}).encode()
        request = urllib.request.Request(f"{KUSTO_URL}/v1/rest/{kind}", data=body,
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return json.load(response)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            try:
                detail = json.loads(detail)["error"]["@message"]
            except (ValueError, KeyError):
                pass
            raise RuntimeError(f"Kusto: {detail[:400]}") from None

    def setup(self):
        # Create both tables with their full column lists.
        for table, columns in SCHEMAS.items():
            spec = ", ".join(f"['{name}']:{kind}" for name, kind in columns.items())
            self._call("mgmt", f".create-merge table {table} ({spec})")

    def run(self, query, table, rows):
        """Replace the table's contents with `rows`; return (hit count, rows loaded)."""
        self._call("mgmt", f".clear table {table} data")
        if rows:
            body = "\n".join(json.dumps(r) for r in rows)
            self._call("mgmt", f".ingest inline into table {table} with (format='json') <|\n{body}")
        result = self._call("query", query.strip() + "\n| count")
        return int(result["Tables"][0]["Rows"][0][0]), len(rows)


# --- Main ---------------------------------------------------------------------

def read_env():
    if not ENV_FILE.exists():
        raise SystemExit(f"{ENV_FILE} not found. Start the engines first: scripts/engines.sh up")
    values = dict(line.split("=", 1) for line in ENV_FILE.read_text().splitlines() if "=" in line)
    return values["SPLUNK_PASSWORD"], values["SPLUNK_HEC_TOKEN"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules-dir", default="rules", type=Path)
    parser.add_argument("--cases-dir", default="tests/cases", type=Path)
    parser.add_argument("--zircolite", type=Path,
                        default=Path(os.environ.get("ZIRCOLITE", "tools/zircolite/Zircolite")))
    parser.add_argument("--rule", help="only validate this rule (file name without .yml)")
    args = parser.parse_args()

    password, hec_token = read_env()
    splunk, kusto = Splunk(password, hec_token), Kusto()
    splunk.setup()
    kusto.setup()

    failures = 0
    report = ["| Rule | Target | Sample | Events loaded | Zircolite | Engine | Result |", "|---|---|---|---|---|---|---|"]
    events_cache = {}  # sample -> flattened events (the same for every rule)
    counts_cache = {}  # (rule, sample) -> Zircolite hit count (the same for every target)

    for rule_path in sorted(args.rules_dir.rglob("*.yml")):
        name = rule_path.stem
        if args.rule and name != args.rule:
            continue
        case = yaml.safe_load((args.cases_dir / f"{name}.yml").read_text(encoding="utf-8"))
        pipelines = case.get("pipelines", DEFAULT_PIPELINES)
        samples = [Path(p["file"]) for p in case.get("positive") or []]
        samples += [Path(n["file"] if isinstance(n, dict) else n) for n in case.get("negative") or []]
        print(f"\n{rule_path}")

        for target, info in TARGETS.items():
            query_file = info["dir"] / f"{name}{info['ext']}"
            if not query_file.exists():
                print(f"  SKIP  {target}: no converted query (unsupported)")
                report.append(f"| {name} | {target} | — | — | — | — | skipped (not converted) |")
                continue
            query = query_file.read_text(encoding="utf-8")

            for sample in samples:
                try:
                    if (name, sample) not in counts_cache:
                        counts_cache[(name, sample)] = count_hits(args.zircolite, rule_path, sample, pipelines)
                    expected = counts_cache[(name, sample)]
                    if sample not in events_cache:
                        events_cache[sample] = read_events(args.zircolite, sample, rule_path)
                    events = events_cache[sample]
                    if target == "splunk":
                        got, loaded = splunk.run(query, sample, events, correlation_group_by(rule_path))
                    else:
                        table = query.split()[0]
                        mapper = TABLE_MAPPERS[table]
                        rows = [typed_row(r, table) for r in map(mapper, events) if r]
                        got, loaded = kusto.run(query, table, rows)
                    detail = f"{got} hit(s), Zircolite {expected}, {loaded} event(s) loaded"
                    if loaded == 0 and expected == 0:
                        # e.g. a System-log negative against a Security-log query:
                        # nothing to test here, and not a failure.
                        passed, result = True, "N/A"
                    else:
                        passed = got == expected and loaded > 0
                        result = "PASS" if passed else "FAIL"
                except (RuntimeError, urllib.error.URLError, OSError) as e:
                    passed, result, expected, got, loaded, detail = False, "ERROR", "?", "?", "?", str(e)
                failures += not passed
                print(f"  {result:5} {target}: {sample.name}: {detail}")
                report.append(f"| {name} | {target} | {sample.name} | {loaded} | {expected} | {got} | {result} |")

    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_FILE.write_text("\n".join(report) + "\n", encoding="utf-8")
    print()
    if failures:
        print(f"{failures} check(s) failed. See {RESULTS_FILE}.")
        return 1
    print(f"All converted queries match Zircolite. See {RESULTS_FILE}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
