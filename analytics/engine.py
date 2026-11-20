"""Compile trusted Sigma-style rules and query immutable Parquet partitions."""

import argparse
import json
from pathlib import Path

import duckdb
import yaml

ROOT = Path(__file__).resolve().parents[1]
FIELDS = {"kind", "outcome"}
SELECT = """
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
), events AS (
    SELECT * FROM raw WHERE {selection}
    QUALIFY row_number() OVER (
      PARTITION BY metadata.product.name, metadata.uid, payload_sha256 ORDER BY time
    ) = 1
)
"""

# Correlations return the triggering event and its event-time timestamp.
QUERIES = {
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


def compile_rules(parquet, directory=ROOT / "rules"):
    queries = []
    seen = set()
    for path in sorted(directory.glob("*.yaml")):
        rule = yaml.safe_load(path.read_text())
        name = rule["id"]
        if not isinstance(name, str) or name in seen:
            raise ValueError(f"invalid or duplicate rule id in {path}")
        seen.add(name)
        detection = rule["detection"]
        if set(detection) != {"selection", "condition"} or detection["condition"] != "selection":
            raise ValueError(f"unsupported Sigma condition in {path}")
        selection = detection["selection"]
        if not isinstance(selection, dict) or not selection or not set(selection) <= FIELDS:
            raise ValueError(f"unsupported Sigma selection in {path}")
        predicates, args = [], [str(parquet)]
        for field, values in selection.items():
            values = [values] if isinstance(values, str) else values
            if not isinstance(values, list) or not values or not all(isinstance(v, str) for v in values):
                raise ValueError(f"invalid selection values in {path}")
            predicates.append(f"{field} IN ({','.join('?' for _ in values)})")
            args.extend(values)
        correlation = rule["correlation"].copy()
        template = correlation.pop("type")
        options = OPTIONS.get(template)
        if options is None or set(options) != set(correlation):
            raise ValueError(f"invalid correlation options in {path}")
        for field, expected in options.items():
            value = correlation[field]
            if (type(value) is not expected or (expected is int and value <= 0)
                    or (expected is list and not all(isinstance(v, str) for v in value))):
                raise ValueError(f"invalid {field} in {path}")
            args.append(value)
        sql = SELECT.format(selection=" AND ".join(predicates)) + QUERIES[template]
        queries.append({"id": name, "sql": sql + " ORDER BY 2,1", "args": args})
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
    with duckdb.connect() as db:
        return [
            (query["id"], event, timestamp)
            for query in queries
            for event, timestamp in db.execute(query["sql"], query["args"]).fetchall()
        ]


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
