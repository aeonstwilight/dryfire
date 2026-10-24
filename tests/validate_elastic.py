"""Elasticsearch side of `make validate-elastic` (M5): load test events, run ES|QL.

Used by tests/run_validate.py with `--engines elastic`. Start the engine with
`scripts/engines.sh up-elastic`.

How events are loaded (the field names Elastic's own integrations write):

  - Windows events go to the data stream of the integration that collects
    their channel: Sysmon -> logs-windows.sysmon_operational-dryfire, Security
    -> logs-system.security-dryfire, System -> logs-system.system-dryfire.
    EventID -> event.code, Channel -> winlog.channel, Provider_Name ->
    winlog.provider_name; the Sysmon fields the integration (and the
    ecs_windows conversion pipeline) puts in ECS fields go there (see
    SYSMON_ECS); every other event field goes to winlog.event_data.<name>.
  - CloudTrail records go to logs-aws.cloudtrail-dryfire with the field
    names of pipelines/elastic_cloudtrail.yml (the conversion's own mapping),
    and requestParameters / additionalEventData as Map.toString() text in
    aws.cloudtrail.request_parameters / additional_eventdata, as the AWS
    integration writes them (ConsoleLogin's result goes to event.outcome,
    lower-cased).
  - Every string is stored as a keyword (whole value, no length limit), so
    ES|QL compares the full value. Real integrations type some of these
    fields differently (wildcard, text sub-fields); the ES|QL string functions
    used by the queries see the same value either way.
  - Each sample's events get their own dryfire_file label and each query is
    limited to it, as in Splunk.

The engine runs with security on and a random password per run, from
build/validate/elastic.env (written by engines.sh).
"""

import base64
import ipaddress
import json
import re
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

import yaml

ELASTIC_URL = "http://localhost:9200"
ENV_FILE = Path("build/validate/elastic.env")

SYSMON = "microsoft-windows-sysmon/operational"
WINDOWS_STREAMS = {
    SYSMON: "logs-windows.sysmon_operational-dryfire",
    "security": "logs-system.security-dryfire",
    "system": "logs-system.system-dryfire",
}
CLOUDTRAIL_STREAM = "logs-aws.cloudtrail-dryfire"

WINDOWS_COMMON = {"EventID": "event.code", "Channel": "winlog.channel", "Provider_Name": "winlog.provider_name",
                  # Security logon events (4624, 4625, 4771): the source address, an ip field in ECS
                  "IpAddress": "source.ip"}
# Sysmon event ID -> fields that Elastic keeps in ECS fields (the same names the
# ecs_windows pipeline converts rule fields to); other fields stay in winlog.event_data.
SYSMON_ECS = {
    "1": {"Image": "process.executable", "CommandLine": "process.command_line",
          "ParentImage": "process.parent.executable", "OriginalFileName": "process.pe.original_file_name"},
    "10": {"SourceImage": "process.executable"},
    "17": {"PipeName": "file.name", "Image": "process.executable"},
    "18": {"PipeName": "file.name", "Image": "process.executable"},
    # Registry value set: the integration splits TargetObject into registry.*
    # (path is the one our rules use) and puts Details in registry.data.strings,
    # a list (string values unchanged; it rewrites DWORD/QWORD values as numbers,
    # which no rule matches).
    "13": {"TargetObject": "registry.path", "Details": "registry.data.strings", "Image": "process.executable"},
}

# CloudTrail field -> Elastic field, from the conversion pipeline, so loaded
# documents and converted queries agree. Request and additional-data fields are
# left out: the whole requestParameters and additionalEventData objects go into
# aws.cloudtrail.request_parameters / additional_eventdata below, as text.
CLOUDTRAIL_PIPELINE = Path("pipelines/elastic_cloudtrail.yml")
CLOUDTRAIL_FIELDS = {
    field: target for field, target in next(
        t["mapping"] for t in yaml.safe_load(CLOUDTRAIL_PIPELINE.read_text(encoding="utf-8"))["transformations"]
        if t["type"] == "field_name_mapping").items()
    if not field.startswith(("requestParameters.", "additionalEventData."))
}

# Our own index template for the test data streams (logs-*-dryfire): every
# string a keyword, no guessing of dates or numbers from strings.
INDEX_TEMPLATE = {
    "index_patterns": ["logs-*-dryfire"],
    "data_stream": {},
    "priority": 500,
    "template": {
        "settings": {"number_of_replicas": 0},
        "mappings": {
            "date_detection": False,
            "numeric_detection": False,
            "dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}],
            # source.ip is an ip field, as in the integrations (values that
            # aren't IPs, such as "-", are left out when loading)
            "properties": {"@timestamp": {"type": "date"}, "source": {"properties": {"ip": {"type": "ip"}}}},
        },
    },
}


def java_text(value):
    """A value as Java's toString() writes it ({a=1, b=[x, y]}), as the AWS integration stores requestParameters."""
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k}={java_text(v)}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(java_text(v) for v in value) + "]"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def nested_value(event, path):
    value = event
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def to_document(event):
    """Return (data stream, document) for one event, or None if no data stream takes it."""
    if "eventVersion" in event and "eventSource" in event:  # CloudTrail record
        doc = {target: nested_value(event, field) for field, target in CLOUDTRAIL_FIELDS.items()}
        if event.get("requestParameters") is not None:
            doc["aws.cloudtrail.request_parameters"] = java_text(event["requestParameters"])
        if event.get("additionalEventData") is not None:
            doc["aws.cloudtrail.additional_eventdata"] = java_text(event["additionalEventData"])
        if doc.get("event.outcome"):
            # The integration lower-cases ConsoleLogin's Success/Failure into event.outcome.
            doc["event.outcome"] = str(doc["event.outcome"]).lower()
        doc["@timestamp"] = event.get("eventTime")
        return CLOUDTRAIL_STREAM, {k: v for k, v in doc.items() if v is not None}
    channel = str(event.get("Channel", "")).lower()
    stream = WINDOWS_STREAMS.get(channel)
    if stream is None:
        return None
    ecs = dict(WINDOWS_COMMON)
    if channel == SYSMON:
        ecs.update(SYSMON_ECS.get(str(event.get("EventID")), {}))
    doc = {}
    for field, value in event.items():
        if value in (None, ""):
            continue
        target = ecs.get(field, f"winlog.event_data.{field}")
        if target == "source.ip" and not is_ip(value):
            continue  # "-" for local logons: an ip field can't hold it
        # registry.data.strings is a list in the integration's documents.
        doc[target] = [str(value)] if target == "registry.data.strings" else str(value)
    doc["@timestamp"] = iso_time(event.get("SystemTime") or event.get("UtcTime"))
    return stream, doc


def is_ip(value):
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def iso_time(value):
    """A Windows event time as ISO 8601 for @timestamp. Sysmon's UtcTime is
    "2026-10-17 12:00:00.000"; anything unreadable gets a fixed time (no
    Windows rule depends on event times)."""
    text = str(value or "").strip().replace(" ", "T", 1)
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return "2026-01-01T00:00:00Z"
    return text if text.endswith("Z") or "+" in text[10:] else text + "Z"


class Elastic:
    def __init__(self, password):
        self.auth = "Basic " + base64.b64encode(f"elastic:{password}".encode()).decode()
        self.loaded = {}  # sample path -> (dryfire_file value, number of documents)
        self.run_id = uuid.uuid4().hex[:8]

    def _call(self, method, path, body=None, ndjson=False):
        data = None
        if body is not None:
            data = (body if ndjson else json.dumps(body)).encode()
        content_type = "application/x-ndjson" if ndjson else "application/json"
        request = urllib.request.Request(ELASTIC_URL + path, data=data, method=method,
                                         headers={"Authorization": self.auth, "Content-Type": content_type})
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return json.load(response)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            try:
                detail = json.loads(detail)["error"]["reason"]
            except (ValueError, KeyError, TypeError):
                pass
            raise RuntimeError(f"Elasticsearch: {str(detail)[:400]}") from None

    def setup(self):
        """Index template and empty data streams, so every query's `from` finds its stream."""
        self._call("PUT", "/_index_template/dryfire-logs", INDEX_TEMPLATE)
        for stream in list(WINDOWS_STREAMS.values()) + [CLOUDTRAIL_STREAM]:
            try:
                self._call("PUT", f"/_data_stream/{stream}")
            except RuntimeError as e:
                if "already exists" not in str(e):
                    raise

    def load(self, sample, events):
        """Send a sample's events once; return (dryfire_file value, number of documents)."""
        if sample in self.loaded:
            return self.loaded[sample]
        file_id = f"{self.run_id}-{len(self.loaded)}"
        lines = []
        for event in events:
            mapped = to_document(event)
            if mapped:
                stream, doc = mapped
                doc["dryfire_file"] = file_id
                lines += [json.dumps({"create": {"_index": stream}}), json.dumps(doc)]
        for i in range(0, len(lines), 1000):
            result = self._call("POST", "/_bulk", "\n".join(lines[i:i + 1000]) + "\n", ndjson=True)
            if result.get("errors"):
                first = next(item for item in result["items"] if "error" in item["create"])
                raise RuntimeError(f"Elasticsearch bulk load failed: {first['create']['error']}")
        self._call("POST", "/logs-*-dryfire/_refresh")
        self.loaded[sample] = (file_id, len(lines) // 2)
        return self.loaded[sample]

    def run(self, query, sample, events, group_by=None):
        """Return (hit count, number of documents loaded for this sample)."""
        file_id, loaded = self.load(sample, events)
        # Limit the query to this sample: the first part is `from <streams> metadata ...`.
        source, rest = query.strip().split(" | ", 1)
        esql = f'{source} | where dryfire_file == "{file_id}" | {rest}'
        if group_by:
            # A correlation query returns one row per time bucket and group over
            # the threshold; count the distinct groups (the converted field
            # names are in its `stats ... by timebucket, <fields>` line).
            fields = re.search(r"by timebucket, (.+)$", rest, flags=re.M).group(1)
            esql += f" | stats rows = count() by {fields}"
        esql += " | stats count = count()"
        result = self._call("POST", "/_query", {"query": esql})
        return int(result["values"][0][0]), loaded


def read_password():
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("ELASTIC_PASSWORD="):
            return line.split("=", 1)[1]
    raise RuntimeError(f"No ELASTIC_PASSWORD in {ENV_FILE}; run scripts/engines.sh up-elastic")
