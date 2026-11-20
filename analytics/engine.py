"""Compile trusted Sigma-style rules and query immutable Parquet partitions."""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path

import duckdb
import yaml

ROOT = Path(__file__).resolve().parents[1]
FIELDS = {
    "kind": "kind", "outcome": "outcome", "actor_user": "account",
    "src_ip": "ip", "src_endpoint.ip": "ip", "actor.user.uid": "account",
    "unmapped.kind": "kind", "unmapped.outcome": "outcome",
    "scope": "scope", "asn": "asn", "device": "device",
}
DEFAULT_DEDUP_MINUTES = 5

# Convert validated text to a numeric address without a downloadable extension.
IP_CTES = r"""
, address_parts AS (
    SELECT *, regexp_extract(ip, '[^:]+$') AS ip_suffix
    FROM raw
), numeric_suffix AS (
    SELECT *, CASE
        WHEN regexp_full_match(ip_suffix, '(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}')
             AND list_max(list_transform(string_split(ip_suffix, '.'),
                                         part -> try_cast(part AS BIGINT)))<=255
        THEN list_reduce(list_transform(string_split(ip_suffix, '.'),
                                        part -> try_cast(part AS BIGINT)),
                         (acc, part) -> acc*256+part)
    END AS suffix_number
    FROM address_parts
), addresses AS (
    SELECT *, CASE WHEN ip=ip_suffix THEN suffix_number END AS ipv4_number,
           CASE WHEN contains(ip, ':') AND suffix_number IS NOT NULL
                THEN left(ip, length(ip)-length(ip_suffix))
                     || hex(suffix_number // 65536) || ':' || hex(suffix_number % 65536)
                ELSE ip END AS ipv6_text
    FROM numeric_suffix
), split_ips AS (
    SELECT *, string_split(ipv6_text, '::') AS ip_halves,
           string_split(ipv6_text, ':') AS ip_parts,
           len(list_filter(string_split(ipv6_text, ':'), part -> part<>'')) AS group_count
    FROM addresses
), expanded AS (
    SELECT *, CASE WHEN len(ip_halves)=2 THEN list_concat(
        list_filter(string_split(ip_halves[1], ':'), part -> part<>''),
        list_transform(range(greatest(0, 8-group_count)), i -> '0'),
        list_filter(string_split(ip_halves[2], ':'), part -> part<>'')
    ) ELSE ip_parts END AS ip_groups
    FROM split_ips
), numeric_ips AS (
    SELECT *,
        CASE WHEN len(ip_groups)=8 AND
                  (len(ip_halves)=1 OR (len(ip_halves)=2 AND group_count<8 AND
                   NOT contains(ipv6_text, ':::') AND
                   NOT (starts_with(ipv6_text, ':') AND NOT starts_with(ipv6_text, '::')) AND
                   NOT (ends_with(ipv6_text, ':') AND NOT ends_with(ipv6_text, '::')))) AND
                  list_bool_and(list_transform(ip_groups,
                      part -> regexp_full_match(part, '[0-9a-fA-F]{1,4}')))
             THEN list_reduce(list_transform(ip_groups,
                       part -> cast(try_cast('0x' || part AS BIGINT) AS UHUGEINT)),
                       (acc, part) -> acc*65536+part)
        END AS ipv6_number
    FROM expanded
)
"""


RAW = """
WITH raw AS (
    SELECT *, lower(trim(actor.user.uid)) AS account,
           coalesce(src_endpoint.ip, '') AS ip,
           coalesce(src_endpoint.asn, '') AS asn,
           coalesce(src_endpoint.device, '') AS device,
           src_endpoint.latitude AS lat, src_endpoint.longitude AS lon,
           unmapped.kind AS kind, unmapped.outcome AS outcome,
           unmapped.scope AS scope, unmapped.token AS token,
           metadata.uid AS event_id
    FROM read_parquet(?, hive_partitioning=false)
)
"""
EVENTS = """
, events AS (
    SELECT * FROM {source} WHERE {selection}
    QUALIFY row_number() OVER (
      PARTITION BY metadata.product.name, metadata.uid, payload_sha256 ORDER BY time
    ) = 1
)
"""

# Correlations return the triggering event and its event-time timestamp.
QUERIES = {
    "match": "SELECT event_id,time FROM events",
    "window": """
    , settings AS (SELECT ?::BIGINT AS duration, ?::BIGINT AS threshold, ?::BIGINT AS min_ips)
    , counts AS (
      SELECT product,event_id,time,
             count(DISTINCT account) OVER w AS accounts,
             count(DISTINCT nullif(ip,'')) OVER w AS sources,
             count(DISTINCT account) OVER prior AS previous_accounts,
             count(DISTINCT nullif(ip,'')) OVER prior AS previous_sources
      FROM (
        SELECT metadata.product.name AS product,event_id,time,account,ip
        FROM events WHERE account<>''
      )
      CROSS JOIN settings
      WINDOW w AS (PARTITION BY product ORDER BY time RANGE BETWEEN duration PRECEDING AND CURRENT ROW),
             prior AS (PARTITION BY product ORDER BY time RANGE BETWEEN duration PRECEDING AND 1 PRECEDING)
    )
    SELECT min(event_id) AS event_id,time
    FROM counts CROSS JOIN settings WHERE accounts>=threshold AND sources>=min_ips
      AND (previous_accounts<threshold OR previous_sources<min_ips)
    GROUP BY product,time
    """,
    "spray": """
    , buckets AS (
      SELECT a.event_id,a.time,b.account,count(*) AS attempts
      FROM events a JOIN events b ON a.ip=b.ip AND b.time BETWEEN a.time-? AND a.time
      WHERE a.ip<>'' AND b.account<>'' GROUP BY ALL
    )
    SELECT event_id,time FROM buckets GROUP BY ALL
    HAVING count(*)>=? AND max(attempts)<=?
    """,
    "mfa": """
    SELECT a.event_id,a.time FROM events a JOIN events d ON a.account=d.account
    WHERE a.account<>'' AND a.outcome='accept' AND d.outcome='deny'
      AND d.time>=a.time-? AND d.time<a.time
      AND a.ip<>'' AND a.asn<>'' AND d.ip<>'' AND d.asn<>''
    GROUP BY a.event_id,a.time,a.ip,a.asn
    HAVING count(*)>=? AND count(*) FILTER (WHERE d.ip=a.ip OR d.asn=a.asn)=0
    """,
    "travel": """
    , clean AS (
      SELECT * FROM events WHERE asn<>'' AND NOT list_contains(?,asn)
      AND NOT list_contains(?,ip) AND lat BETWEEN -90 AND 90 AND lon BETWEEN -180 AND 180
    ), pairs AS (
      SELECT *,lag(time) OVER w AS prev_time,lag(lat) OVER w AS prev_lat,lag(lon) OVER w AS prev_lon
      FROM clean WHERE account<>''
      WINDOW w AS (PARTITION BY account ORDER BY time,event_id)
    )
    SELECT event_id,time FROM pairs
    WHERE time-prev_time BETWEEN 1 AND ?
    AND 12742*asin(sqrt(least(1.0,
          pow(sin(radians(lat-prev_lat)/2),2)
          + cos(radians(lat))*cos(radians(prev_lat))*pow(sin(radians(lon-prev_lon)/2),2)
    ))) > ?*(time-prev_time)/3600000.0
    """,
    "scope": """
    SELECT event_id,time FROM events
    WHERE regexp_matches(lower(coalesce(scope,'')),?)
    """,
    "replay": """
    , observations AS (
      SELECT min(event_id) AS event_id, time, token, asn, device
      FROM events
      WHERE token<>'' AND asn<>'' AND device<>''
      GROUP BY time, token, asn, device
    )
    SELECT DISTINCT a.event_id,a.time FROM observations a JOIN observations b ON a.token=b.token
    WHERE a.asn<>b.asn AND a.device<>b.device AND b.time>=a.time-?
      AND (b.time<a.time OR (b.time=a.time AND b.event_id<a.event_id))
    """,
}

OPTIONS = {
    "spray": {"window_ms": int, "min_accounts": int, "max_attempts": int},
    "mfa": {"window_ms": int, "min_denials": int},
    "travel": {"trusted_asns": list, "trusted_ips": list, "window_ms": int, "max_kph": int},
    "scope": {"scope_pattern": str},
    "replay": {"window_ms": int},
}


def compile_predicates(fields, args):
    if not isinstance(fields, dict) or not fields:
        raise ValueError("expected a nonempty selection or filter mapping")
    predicates = []
    for key, values in fields.items():
        field, separator, modifier = key.partition("|")
        column = FIELDS.get(field)
        if column is None or (separator and modifier not in ("contains", "startswith", "cidr")):
            raise ValueError(f"unsupported field or modifier: {key}")
        values = [values] if isinstance(values, str) else values
        if not isinstance(values, list) or not values or not all(isinstance(v, str) for v in values):
            raise ValueError(f"invalid values for {key}")
        if modifier == "cidr":
            if column != "ip":
                raise ValueError("cidr requires an IP field")
            ranges = []
            for value in values:
                network = ipaddress.ip_network(value, strict=False)
                ranges.append(f"ipv{network.version}_number BETWEEN CAST(? AS UHUGEINT) AND CAST(? AS UHUGEINT)")
                args.extend((str(int(network.network_address)), str(int(network.broadcast_address))))
            predicates.append("(" + " OR ".join(ranges) + ")")
        elif modifier:
            function = {"contains": "contains", "startswith": "starts_with"}[modifier]
            predicates.append("(" + " OR ".join(f"{function}({column}, ?)" for _ in values) + ")")
            args.extend(values)
        else:
            predicates.append(f"{column} IN ({','.join('?' for _ in values)})")
            args.extend(values)
    return " AND ".join(predicates)


def compile_correlation(correlation, args):
    if correlation is None:
        return "match"
    options = correlation.copy()
    template = options.pop("type", None)
    if template == "window":
        aggregate = options.pop("aggregate", None)
        minutes = options.pop("window_minutes", None)
        threshold = options.pop("threshold", None)
        sources = options.pop("min_distinct_ips", 0)
        if (options or aggregate != "count_distinct(actor_user)"
                or any(type(v) is not int or v <= 0 or v > (2**63 - 1) // 60000
                       for v in (minutes, threshold))
                or type(sources) is not int or not 0 <= sources < 2**63):
            raise ValueError("invalid sliding-window options")
        args.extend((minutes * 60000, threshold, sources))
        return template
    schema = OPTIONS.get(template)
    if schema is None or set(schema) != set(options):
        raise ValueError("invalid correlation options")
    for field, expected in schema.items():
        value = options[field]
        if (type(value) is not expected or (expected is int and not 0 < value < 2**63)
                or (expected is list and not all(isinstance(v, str) for v in value))):
            raise ValueError(f"invalid {field}")
        args.append(value)
    return template


def compile_rules(parquet, directory=ROOT / "rules"):
    queries = []
    seen = set()
    for path in sorted(directory.glob("*.yaml")):
        try:
            rule = yaml.safe_load(path.read_text())
            name = rule["id"]
            if not isinstance(name, str) or not name or name in seen:
                raise ValueError("invalid or duplicate rule id")
            seen.add(name)
            detection = rule["detection"]
            filtered = "filter" in detection
            keys = {"selection", "condition"} | ({"filter"} if filtered else set())
            if set(detection) != keys or detection["condition"] != (
                    "selection and not filter" if filtered else "selection"):
                raise ValueError("unsupported Sigma condition")
            args = [str(parquet)]
            selection = compile_predicates(detection["selection"], args)
            if filtered:
                excluded = compile_predicates(detection["filter"], args)
                selection += f" AND NOT coalesce(({excluded}), false)"
            template = compile_correlation(rule.get("correlation"), args)
            dedup = rule.get("dedup_minutes", DEFAULT_DEDUP_MINUTES)
            if type(dedup) is not int or not 0 <= dedup <= (2**63 - 1) // 60000:
                raise ValueError("invalid dedup_minutes")
            uses_cidr = "ipv4_number" in selection or "ipv6_number" in selection
            sql = RAW + (IP_CTES if uses_cidr else "")
            sql += EVENTS.format(source="numeric_ips" if uses_cidr else "raw", selection=selection)
            sql += QUERIES[template]
            queries.append({"id": name, "sql": sql + " ORDER BY 2,1", "args": args,
                            "dedup_ms": dedup * 60000})
        except (AttributeError, KeyError, TypeError, ValueError, yaml.YAMLError) as err:
            raise ValueError(f"{path}: {err}") from err
    if not queries:
        raise ValueError("no detection rules found")
    return queries


SCHEMA = """
    time BIGINT,
    actor STRUCT(user STRUCT(uid VARCHAR)),
    metadata STRUCT(uid VARCHAR, product STRUCT(name VARCHAR)),
    src_endpoint STRUCT(ip VARCHAR, asn VARCHAR, device VARCHAR, latitude DOUBLE, longitude DOUBLE),
    unmapped STRUCT(kind VARCHAR, outcome VARCHAR, scope VARCHAR, token VARCHAR),
    payload_sha256 VARCHAR, original JSON
"""


def export_parquet(events, directory):
    """Publish one immutable partitioned snapshot to a new directory."""
    from tempfile import TemporaryDirectory

    directory = Path(directory)
    directory.parent.mkdir(parents=True, exist_ok=True)
    if directory.exists():
        raise FileExistsError(directory)
    with TemporaryDirectory(dir=directory.parent) as temp, duckdb.connect() as db:
        destination = Path(temp) / "snapshot"
        db.execute(f"CREATE TABLE telemetry ({SCHEMA})")
        rows = [(e["time"], e["actor"], {
                "uid": e["metadata"]["uid"],
                "product": {"name": e["metadata"]["product"]["name"]},
            }, {k: e["src_endpoint"].get(k) for k in ("ip", "asn", "device", "latitude", "longitude")},
                {k: e["unmapped"].get(k) for k in ("kind", "outcome", "scope", "token")},
                e["payload_sha256"], json.dumps(e)) for e in events]
        if rows:
            db.executemany("INSERT INTO telemetry VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
            db.execute(
                """COPY (SELECT *, CAST(to_timestamp(time/1000.0) AT TIME ZONE 'UTC' AS DATE) AS day
                          FROM telemetry)
                   TO ? (FORMAT PARQUET, PARTITION_BY (day))""",
                [str(destination)],
            )
        else:
            empty_partition = destination / "day=empty"
            empty_partition.mkdir(parents=True)
            db.execute("COPY telemetry TO ? (FORMAT PARQUET)", [str(empty_partition / "empty.parquet")])
        destination.rename(directory)
    return str(directory / "day=*" / "*.parquet")


def evaluate(queries):
    findings = []
    last_alert = {}
    with duckdb.connect() as db:
        for query in queries:
            rule = query["id"]
            window = query.get("dedup_ms", 0)
            for event, timestamp in db.execute(query["sql"], query["args"]).fetchall():
                if window:
                    content = f"{len(rule.encode())}:{rule}{event}".encode()
                    digest = hashlib.sha256(content).digest()
                    previous = last_alert.get(digest)
                    if previous is not None and timestamp - previous < window:
                        continue
                    last_alert[digest] = timestamp
                findings.append((rule, event, timestamp))
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["compile", "run", "export"])
    parser.add_argument("path", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--journal", type=Path, action="append", default=[])
    args = parser.parse_args()
    if args.command == "export":
        if args.output is None:
            parser.error("export requires --output")
        directories = [args.path, *args.journal]
        if any(not path.is_dir() for path in directories):
            parser.error("each journal must exist")
        files = [path for journal in directories for path in sorted(journal.glob("*.jsonl"))]
        events = [event for path in files for event in (json.loads(path.read_text())["events"] or [])]
        print(export_parquet(events, args.output))
        return
    queries = compile_rules(args.path)
    print(json.dumps(queries if args.command == "compile" else evaluate(queries)))


if __name__ == "__main__":
    main()
