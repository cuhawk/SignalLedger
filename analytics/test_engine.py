from pathlib import Path

from analytics.benchmark import run_suite
from analytics.engine import compile_rules, evaluate, export_parquet
from analytics.fixtures import traces


def test_detection_and_evasion(tmp_path):
    _, incidents, alerts, _ = run_suite(tmp_path / "partitions")
    got = {(rule, uid) for rule, uid, _ in alerts}
    expected = {(i.rule, uid) for i in incidents for uid in i.triggers if not uid.startswith("slow-")}
    assert got == expected
    assert len(alerts) == len(got)
    assert not any(uid.startswith("vpn-") or uid.startswith("slow-") for _, uid in got)


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
