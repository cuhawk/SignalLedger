import base64
import json
import subprocess

import pytest

from analytics.engine import ROOT, compile_rules, export_parquet
from analytics.benchmark import run_suite


def command(cli, *args):
    return subprocess.run([cli, *args], capture_output=True, text=True)


def write(path, value):
    path.write_text(json.dumps(value))
    return str(path)


def test_go_duckdb_matches_python(cli, tmp_path):
    _, _, alerts, _ = run_suite(tmp_path / "parquet")
    queries = compile_rules(tmp_path / "parquet" / "day=*" / "*.parquet")
    result = command(cli, "detect", "--queries", write(tmp_path / "queries", queries))
    assert result.returncode == 0, result.stderr
    assert [(row["Rule"], row["EventID"], row["TimeMS"]) for row in json.loads(result.stdout)] == alerts


@pytest.fixture
def signed(cli, tmp_path):
    # RFC 8032 test vector 1. This fixed key is used only for tests.
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    key = write(tmp_path / "private", base64.b64encode(seed + public).decode())
    pub = write(tmp_path / "public", base64.b64encode(public).decode())
    start, end = "2025-01-01T00:00:00Z", "2025-01-01T01:00:00Z"
    records = [{"time": start, "kind": "heartbeat", "data": label}
               for label in ("alpha", "bravo", "charlie")]
    args = ["collect", "--private-key", key, "--start", start, "--end", end]
    result = command(cli, *args, "--window", write(tmp_path / "records", records))
    assert result.returncode == 0, result.stderr
    bundle = json.loads(result.stdout)
    return pub, args, bundle, end


def test_cli_tamper_and_liveness(cli, tmp_path, signed):
    pub, collect, bundle, end = signed
    root, records = bundle["root"], bundle["records"]
    proof = write(tmp_path / "proof", bundle["proofs"][0])

    def verify(statement, *, window=None, leaf=None):
        args = ["verify", "--pubkey", pub, "--root", write(tmp_path / "root", statement)]
        if window is not None:
            args.extend(["--window", write(tmp_path / "window", window)])
        else:
            args.extend(["--proof", proof, "--leaf", write(tmp_path / "leaf", leaf)])
        return command(cli, *args)

    assert verify(root, window=records).stdout.strip() == "PASS"
    assert verify(root, leaf=records[0]).stdout.strip() == "PASS"
    assert verify(root, leaf={**records[0], "data": "alphb"}).returncode == 1
    assert verify(root, window=[records[1], records[0], records[2]]).returncode == 1
    assert verify(root, window=records[:2]).returncode == 1
    adjacent = [{**records[0], "time": end}]
    next_end = "2025-01-01T02:00:00Z"
    neighbor = command(cli, *collect[:3], "--start", end, "--end", next_end,
                       "--window", write(tmp_path / "adjacent", adjacent))
    assert neighbor.returncode == 0, neighbor.stderr
    signed_neighbor = json.loads(neighbor.stdout)
    assert verify(signed_neighbor["root"], window=adjacent).stdout.strip() == "PASS"
    splice = verify(root, window=[*records[:2], signed_neighbor["records"][0]])
    assert splice.returncode == 1 and "timestamp outside window" in splice.stderr
    signature = bytearray(base64.b64decode(root["signature"]))
    signature[0] ^= 1
    forged = {**root, "signature": base64.b64encode(signature).decode()}
    assert verify(forged, window=records).returncode == 1
    empty = command(cli, *collect, "--window", write(tmp_path / "empty", []))
    assert empty.returncode == 1 and "FAIL_EMPTY_WINDOW" in empty.stderr


def test_write_gate_red_team():
    result = subprocess.run(
        ["go", "test", "-race", "-count=1", "-json", "-run", "^TestRedTeam$", "./internal/writegate"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    passed = {message.get("Test") for line in result.stdout.splitlines()
              if (message := json.loads(line))["Action"] == "pass"}
    assert {"TestRedTeam/" + case for case in (
        "replay", "scope_escalation", "state_drift", "atomic_race", "hostile_instruction",
        "wildcard", "read_only",
    )} <= passed


def test_go_alert_hash_dedup_matches_python(cli, tmp_path):
    from analytics.engine import evaluate

    query = {"id": "dedup", "args": [], "dedup_ms": 300,
             "sql": "SELECT 'event', ms FROM (VALUES (1000), (1000), (1299), (1300)) t(ms) ORDER BY ms"}
    result = command(cli, "detect", "--queries", write(tmp_path / "queries", [query]))
    assert result.returncode == 0, result.stderr
    assert [(row["Rule"], row["EventID"], row["TimeMS"]) for row in json.loads(result.stdout)] == evaluate([query])


def test_cli_consistency(cli, tmp_path, signed):
    pub, collect, old, _ = signed
    records = [*old["records"], {**old["records"][-1], "data": "delta"}]
    window = write(tmp_path / "cumulative", records)
    result = command(cli, *collect, "--window", window)
    assert result.returncode == 0, result.stderr
    new = json.loads(result.stdout)
    heads = ["--old-root", write(tmp_path / "old", old["root"]),
             "--new-root", write(tmp_path / "new", new["root"]), "--pubkey", pub]
    result = command(cli, "prove-consistency", *heads, "--window", window)
    assert result.returncode == 0, result.stderr
    proof = write(tmp_path / "proof", json.loads(result.stdout))
    assert command(cli, "verify-consistency", *heads, "--proof", proof).stdout.strip() == "PASS"
    reversed_heads = ["--old-root", heads[3], "--new-root", heads[1], "--pubkey", pub]
    assert command(cli, "verify-consistency", *reversed_heads, "--proof", proof).returncode == 1


def test_rule_check_cli(cli, tmp_path):
    from analytics.rulecheck import read_fixture

    fixture_dir = ROOT / "analytics" / "testdata" / "wave4"
    for name, counts in (("mixed", "12 fixture events, 2 findings"),
                         ("benign", "10 fixture events, 0 findings")):
        result = command(cli, "rule", "check", "--fixture", fixture_dir / f"{name}.fixture.json")
        assert result.returncode == 0, result.stderr
        assert counts in result.stdout

    mixed = fixture_dir / "mixed.fixture.json"
    spec = json.loads(mixed.read_text())
    for item in spec["inputs"]:
        item["path"] = str(fixture_dir / item["path"])
    spec["expected"] = []
    path = write(tmp_path / "mismatch.json", spec)
    result = command(cli, "rule", "check", "--fixture", path)
    assert result.returncode == 1
    assert "fixture mismatch" in result.stderr

    (tmp_path / "bad.yaml").write_text("id: [unterminated\n")
    result = command(cli, "rule", "check", "--rules", tmp_path)
    assert result.returncode == 1
    assert "bad.yaml" in result.stderr

    events, expected = read_fixture(mixed)
    parquet = export_parquet(events, tmp_path / "parquet")
    result = command(cli, "detect", "--queries", write(tmp_path / "queries.json", compile_rules(parquet)))
    assert result.returncode == 0, result.stderr
    assert [[row["Rule"], row["EventID"], row["TimeMS"]]
            for row in json.loads(result.stdout)] == expected
