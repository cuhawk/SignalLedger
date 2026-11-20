"""Measure fixture detections and include verdict counts from executed Go cases."""

import argparse
import json
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter

from analytics.engine import ROOT, compile_rules, evaluate, export_parquet
from analytics.fixtures import traces

REQUIRED = {
    "TestTamper/byte_flip", "TestTamper/reorder", "TestTamper/delete",
    "TestTamper/adjacent_window", "TestTamper/forged_signature", "TestTamper/empty_window",
}


def run_suite(directory):
    events, incidents = traces()
    parquet = export_parquet(events, directory)
    rules = compile_rules(parquet)
    start = perf_counter()
    findings = evaluate(rules)
    elapsed = (perf_counter() - start) * 1000
    return events, incidents, findings, elapsed


def render(report):
    messages = [json.loads(line) for line in report.read_text().splitlines()]
    passed = {msg.get("Test") for msg in messages
              if msg.get("Action") == "pass" and msg.get("Package", "").endswith("/internal/merkle")}
    if not REQUIRED <= passed or any(msg.get("Action") == "fail" for msg in messages):
        raise ValueError("missing successful tamper cases in executed Go test report")
    with TemporaryDirectory() as temp:
        events, incidents, findings, elapsed = run_suite(Path(temp) / "parquet")
    lines = [
        "# Observed detection and tamper metrics", "",
        f"Synthetic events evaluated: {len(events)}. DuckDB query wall time: {elapsed:.1f} ms.", "",
        "| Rule | TP | FP alerts | FN | Precision | Recall | Median event-time latency | FP/1k events |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for rule in sorted({incident.rule for incident in incidents}):
        expected = [incident for incident in incidents if incident.rule == rule]
        alerts = [(event, ts) for label, event, ts in findings if label == rule]
        delays = [min(times) - i.start for i in expected
                  if (times := [ts for event, ts in alerts if event in i.triggers])]
        tp = len(delays)
        fp = sum(not any(event in i.triggers for i in expected) for event, _ in alerts)
        fn = len(expected) - tp
        latency = f"{median(delays) / 1000:.1f} s" if delays else "—"
        precision = f"{tp / (tp + fp):.1%}" if (tp + fp) else "—"
        lines.append(f"| {rule} | {tp} | {fp} | {fn} | {precision} | "
                     f"{tp / len(expected):.1%} | {latency} | {fp * 1000 / len(events):.3f} |")
    lines.extend(["", f"Tamper attempts rejected: {len(REQUIRED & passed)}/{len(REQUIRED)}.", ""])
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks" / "RESULTS.md")
    args = parser.parse_args()
    args.output.write_text(render(args.go_report))
