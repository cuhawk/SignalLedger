from pathlib import Path

from analytics.benchmark import run_suite
from analytics.engine import compile_rules, evaluate, export_parquet
from analytics.fixtures import traces


def test_detection_and_evasion(tmp_path):
    _, incidents, alerts, _ = run_suite(tmp_path / "partitions")
    got = {(rule, uid) for rule, uid, _ in alerts}
    expected = {(i.rule, uid) for i in incidents for uid in i.triggers}
    assert got == expected
    assert len(alerts) == len(got)
    assert not any(uid.startswith("vpn-") for _, uid in got)


def test_rule_selection_is_bound_parameter(tmp_path):
    events, _ = traces()
    parquet = export_parquet(events[:1], tmp_path / "partitions")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yaml").write_text("""
id: parameter-test
detection:
  selection:
    kind: "x') OR TRUE --"
  condition: selection
correlation:
  type: scope
  scope_pattern: '.*'
""")
    queries = compile_rules(parquet, rules)
    assert "OR TRUE" not in queries[0]["sql"]
    assert evaluate(queries) == []


def test_partitions_span_multiple_days(tmp_path):
    events, _ = traces()
    parquet = export_parquet(events, tmp_path / "partitions")
    assert len(list(Path(parquet).parent.parent.glob("day=*"))) >= 3


def test_empty_snapshot_has_no_findings(tmp_path):
    parquet = export_parquet([], tmp_path / "empty")
    assert evaluate(compile_rules(parquet)) == []


def test_sigma_filter_modifiers_and_cidr(tmp_path):
    events, _ = traces()
    candidates = []
    for index, ip in enumerate(("203.0.113.9", "2001:db8::beef", "2001:db8:0:0:0:0:0:f",
                                "203.0.114.4", "2001:db8:::a", "203.0.113.256",
                                "::ffff:203.0.113.18")):
        event = {**events[index], "src_endpoint": {**events[index]["src_endpoint"], "ip": ip},
                 "unmapped": {**events[index]["unmapped"], "scope": "contains_%_literal"}}
        candidates.append(event)
    candidates[2]["unmapped"]["scope"] = "skip_contains_%_literal"
    candidates[3]["unmapped"]["scope"] = None
    parquet = export_parquet(candidates, tmp_path / "partitions")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "filters.yaml").write_text("""
id: modifiers
detection:
  selection:
    actor_user|startswith: [person-, service-]
    src_endpoint.ip|cidr: [203.0.113.0/24, '2001:db8::/32', '::ffff:203.0.113.0/120']
  filter:
    scope|startswith: skip_
    scope|contains: '_%_'
  condition: selection and not filter
""")
    queries = compile_rules(parquet, rules)
    assert "203.0.113.0/24" not in queries[0]["sql"]
    assert [uid for _, uid, _ in evaluate(queries)] == ["base-0-0", "base-0-1", "base-0-6"]


def test_alert_hash_dedup_expiry_is_per_rule():
    sql = """
    SELECT event_id, time FROM (VALUES ('same',1000), ('same',1000), ('same',1100),
           ('other',1100), ('same',1299), ('same',1300)) AS matches(event_id,time)
    ORDER BY time,event_id
    """
    queries = [{"id": name, "sql": sql, "args": [], "dedup_ms": 300}
               for name in ("first", "second")]
    assert evaluate(queries) == [
        (name, event, timestamp)
        for name in ("first", "second")
        for event, timestamp in (("same", 1000), ("other", 1100), ("same", 1300))
    ]


def test_sliding_window_counts_distinct_users_at_inclusive_boundary(tmp_path):
    from analytics.fixtures import DAY, EPOCH, MIN

    events, _ = traces()
    midnight = (EPOCH // DAY + 1) * DAY
    series = (
        (0, "one", "203.0.113.1"),
        (1, "two", "203.0.113.2"),
        (2, "two", "203.0.113.2"),
        (90, "three", "203.0.113.3"),
        (91, "four", "203.0.113.4"),
    )
    candidates = [
        {**events[i], "time": midnight + (offset - 1) * MIN,
         "actor": {"user": {"uid": account}},
         "src_endpoint": {**events[i]["src_endpoint"], "ip": ip},
         "unmapped": {**events[i]["unmapped"], "outcome": "failure"}}
        for i, (offset, account, ip) in enumerate(series)
    ]
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "window.yaml").write_text("""
id: window
detection:
  selection:
    outcome: failure
  condition: selection
correlation:
  type: window
  aggregate: count_distinct(actor_user)
  window_minutes: 90
  threshold: 3
  min_distinct_ips: 2
""")
    parquet = export_parquet(candidates, tmp_path / "partitions")
    assert evaluate(compile_rules(parquet, rules)) == [
        ("window", "base-0-3", midnight + 89 * MIN),
        ("window", "base-0-4", midnight + 90 * MIN),
    ]
