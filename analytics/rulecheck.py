"""Validate Sigma rules and compare DuckDB findings with fixture expectations."""

import argparse
from collections import Counter
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import duckdb

from analytics.engine import ROOT, compile_rules, evaluate, export_parquet
from analytics.native import PRODUCTS, read_events


def read_fixture(fixture):
    events = []
    spec = json.loads(fixture.read_text(encoding="utf-8"))
    if not isinstance(spec, dict) or set(spec) != {"inputs", "expected"}:
        raise ValueError("fixture must contain inputs and expected")
    if not isinstance(spec["inputs"], list) or not spec["inputs"]:
        raise ValueError("fixture inputs must be a nonempty array")
    for item in spec["inputs"]:
        if (not isinstance(item, dict) or set(item) != {"path", "vendor"}
                or not isinstance(item["path"], str) or not item["path"]
                or not isinstance(item["vendor"], str) or item["vendor"] not in PRODUCTS):
            raise ValueError("each input must supply a path and native vendor")
        events.extend(read_events(fixture.parent / item["path"], item["vendor"]))
    if not events:
        raise ValueError("fixture contains no supported events")
    expected = spec["expected"]
    if not isinstance(expected, list) or any(
        not isinstance(row, list) or len(row) != 3
        or any(not isinstance(v, str) or not v for v in row[:2])
        or type(row[2]) is not int for row in expected
    ):
        raise ValueError("expected must be an array of [rule_id, event_id, time_ms] rows")
    return events, expected


def check(rules, fixture):
    events, expected = read_fixture(fixture) if fixture is not None else ([], [])
    with TemporaryDirectory() as temp:
        parquet = export_parquet(events, Path(temp) / "parquet")
        queries = compile_rules(parquet, rules)
        findings = evaluate(queries)
    wanted, actual = Counter(map(tuple, expected)), Counter(findings)
    if wanted != actual:
        raise ValueError(f"fixture mismatch: missing {list((wanted - actual).elements())}; "
                         f"unexpected {list((actual - wanted).elements())}")
    return f"PASS: {len(queries)} rules, {len(events)} fixture events, {len(findings)} findings"


def main():
    parser = argparse.ArgumentParser(prog="signalledger rule check")
    parser.add_argument("--rules", type=Path, default=ROOT / "rules")
    parser.add_argument("--fixture", type=Path)
    args = parser.parse_args()
    try:
        print(check(args.rules, args.fixture))
    except (OSError, TypeError, ValueError, duckdb.Error) as err:
        parser.exit(1, f"{err}\n")


if __name__ == "__main__":
    main()
