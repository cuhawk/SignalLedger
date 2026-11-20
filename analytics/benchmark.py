"""Measure fixture detections and include verdict counts from executed Go cases."""

import argparse
import json
import os
from pathlib import Path
from statistics import median
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import perf_counter

from analytics.engine import ROOT, compile_rules, evaluate, export_parquet
from analytics.fixtures import traces
from analytics.rulecheck import read_fixture

REQUIRED = {
    "TestTamper/byte_flip", "TestTamper/reorder", "TestTamper/delete",
    "TestTamper/adjacent_window", "TestTamper/forged_signature", "TestTamper/empty_window",
}

CONSISTENCY_REQUIRED = {"TestConsistencyTamper/" + case for case in (
    "tampered_hash", "reordered_proof", "truncated_proof", "extra_hash",
    "forged_old_signature", "forged_new_signature", "rewritten_prefix",
    "truncated_log", "rollback", "same_size_fork",
)}
SLOW_RULE = "distributed_password_spray"


def run_suite(directory):
    events, incidents = traces()
    parquet = export_parquet(events, directory)
    rules = compile_rules(parquet)
    start = perf_counter()
    findings = evaluate(rules)
    elapsed = (perf_counter() - start) * 1000
    return events, incidents, findings, elapsed


def native_metrics(base, cli):
    fixtures = ROOT / "analytics" / "testdata" / "wave4"
    mixed = fixtures / "mixed.fixture.json"
    benign = fixtures / "benign.fixture.json"
    events, expected = read_fixture(mixed)
    baseline, _ = read_fixture(benign)
    rules = compile_rules(export_parquet(events, base / "native"))
    start = perf_counter()
    findings = evaluate(rules)
    elapsed = (perf_counter() - start) * 1000
    benign_alerts = evaluate(compile_rules(export_parquet(baseline, base / "native-benign")))
    times = {event["metadata"]["uid"]: event["time"] for event in events}
    rows = [
        "", "## Native CloudTrail and Okta fixtures", "",
        f"DuckDB query wall time across {len(events)} mixed events: {elapsed:.1f} ms.",
        f"Benign-only false positives across all rules: {len(benign_alerts)}/{len(baseline)} events "
        f"({1000 * len(benign_alerts) / len(baseline):.3f} alerts per 1,000 events).", "",
        "| Rule | Recall | Median event-time latency | Baseline FP rate |",
        "| --- | ---: | ---: | ---: |",
    ]
    for rule in sorted({row[0] for row in expected}):
        labels = {tuple(row) for row in expected if row[0] == rule}
        hits = set(findings) & labels
        delay = f"{median(ts - times[event] for _, event, ts in hits)} ms" if hits else "—"
        false_positives = len({event for label, event, _ in benign_alerts if label == rule})
        rows.append(f"| {rule} | {len(hits)}/{len(labels)} | {delay} | "
                    f"{false_positives}/{len(baseline)} ({false_positives / len(baseline):.1%}) |")
    if cli is not None:
        rows.append("")
        for fixture in (mixed, benign):
            result = subprocess.run(
                [str(cli.resolve()), "rule", "check", "--fixture", str(fixture)],
                cwd=ROOT, env=dict(os.environ, SIGNALLEDGER_PYTHON=sys.executable),
                check=True, capture_output=True, text=True,
            )
            rows.append(f"`signalledger rule check` with `{fixture.name}` reported "
                        f"{result.stdout.strip().removeprefix('PASS: ')} and exited 0.")
    return rows


def render(report, cli=None):
    messages = [json.loads(line) for line in report.read_text().splitlines()]
    passed = {msg.get("Test") for msg in messages
              if msg.get("Action") == "pass" and msg.get("Package", "").endswith("/internal/merkle")}
    if (not (REQUIRED | CONSISTENCY_REQUIRED | {"TestConsistencyPrefixes"}) <= passed
            or any(msg.get("Action") == "fail" for msg in messages)):
        raise ValueError("missing successful tamper cases in executed Go test report")
    with TemporaryDirectory() as temp:
        base = Path(temp)
        events, incidents, findings, elapsed = run_suite(base / "parquet")
        parquet = base / "parquet" / "day=*" / "*.parquet"
        legacy = evaluate([q for q in compile_rules(parquet) if q["id"] != SLOW_RULE])
        baseline = [event for event in events if event["metadata"]["uid"].startswith(
            ("base-", "vpn-", "readonly-", "sender-"))]
        benign_alerts = evaluate(compile_rules(export_parquet(baseline, base / "benign")))
        native = native_metrics(base, cli)
    slow = [i for i in incidents if i.rule == SLOW_RULE]
    legacy_hits = len({event for rule, event, _ in legacy if rule == "password_spray"}
                      & set().union(*(i.triggers for i in slow)))
    slow_hits = len({event for rule, event, _ in findings if rule == SLOW_RULE}
                    & set().union(*(i.triggers for i in slow)))
    lines = [
        "# Observed detection and tamper metrics", "",
        f"Synthetic events evaluated: {len(events)}. DuckDB query wall time: {elapsed:.1f} ms.", "",
        f"Distributed slow-spray recall on the same labeled incidents: {legacy_hits}/{len(slow)} "
        f"with the single-source rule, {slow_hits}/{len(slow)} with the distributed rule.",
        f"Benign baseline false positives: {len(benign_alerts)}/{len(baseline)} events "
        f"({1000 * len(benign_alerts) / len(baseline):.3f} alerts per 1,000 events).", "",
        "| Rule | Recall | Median event-time latency | FP/1k events |",
        "| --- | ---: | ---: | ---: |",
    ]
    for rule in sorted({incident.rule for incident in incidents}):
        expected = [incident for incident in incidents if incident.rule == rule]
        alerts = [(event, ts) for label, event, ts in findings if label == rule]
        delays = [min(times) - i.start for i in expected
                  if (times := [ts for event, ts in alerts if event in i.triggers])]
        tp = len(delays)
        fp = sum(not any(event in i.triggers for i in expected) for event, _ in alerts)
        latency = f"{median(delays) / 1000:.1f} s" if delays else "—"
        lines.append(f"| {rule} | "
                     f"{tp / len(expected):.1%} | {latency} | {fp * 1000 / len(events):.3f} |")
    lines.extend([
        "", f"Signed-window tamper attempts rejected: {len(REQUIRED & passed)}/{len(REQUIRED)}.",
        f"Consistency tamper, truncation and rollback cases rejected: "
        f"{len(CONSISTENCY_REQUIRED & passed)}/{len(CONSISTENCY_REQUIRED)}.",
        "Consistency prefix matrix and RFC 6962 proof-vector test passed.",
    ])
    return "\n".join([*lines, *native, ""])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-report", type=Path, required=True)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks" / "RESULTS.md")
    args = parser.parse_args()
    args.output.write_text(render(args.go_report, args.cli))
