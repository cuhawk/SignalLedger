"""Build and time signed compliance reports from the native Parquet fixtures."""

import base64
import json
import subprocess
from time import perf_counter

from analytics.engine import ROOT, compile_rules, export_parquet
from analytics.rulecheck import read_fixture


def _encoded(raw):
    return base64.b64encode(raw).decode("ascii")


def _key(directory, name):
    path = directory / f"{name}.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(path)],
                   check=True, capture_output=True)
    pub = subprocess.check_output(["openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER"])[-32:]
    seed = subprocess.check_output(["openssl", "pkey", "-in", str(path), "-outform", "DER"])[-32:]
    return path, pub, seed


def compliance_cases(directory, cli):
    def run(*args):
        return subprocess.check_output([str(cli), *map(str, args)], text=True)

    def save(name, value):
        path = directory / name
        path.write_text(json.dumps(value))
        return path

    events, _ = read_fixture(ROOT / "analytics/testdata/wave4/mixed.fixture.json")
    queries = save("queries.json", compile_rules(export_parquet(events, directory / "parquet")))
    detections = json.loads(run("detect", "--queries", queries, "--evidence"))
    assert detections
    _, pub, seed = _key(directory, "log")
    private_key = save("private.json", _encoded(seed + pub))
    public_key = save("public.json", _encoded(pub))

    request = {"connector": "test", "action": "disable_user", "target_id": "one"}
    claims = {"Request": request, "StateHash": "a" * 64, "Approvers": ["alice", "bob"],
              "Expiry": "2025-08-02T00:01:00Z", "ID": "approval"}
    payload = directory / "claims.json"
    payload.write_text(json.dumps(claims, separators=(",", ":"), sort_keys=True))
    trusted, signatures = {}, []
    for person in claims["Approvers"]:
        pem, pub, _ = _key(directory, person)
        trusted[person] = _encoded(pub)
        signatures.append(_encoded(subprocess.check_output([
            "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(pem), "-in", str(payload),
        ])))
    approver_keys = save("approvers.json", trusted)
    for case in ("verified", "missing", "unapproved", "invalid_approval_signature", "invalid_window",
                 "unsigned_detection"):
        stamp = "2025-08-02T00:00:00Z"
        records = [] if case == "unsigned_detection" else detections.copy()
        if case != "missing":
            current = signatures.copy()
            if case == "invalid_approval_signature":
                current[0] = _encoded(bytes(64))
            records.extend([
                {"time": stamp, "kind": "connector_write_authorized", "data": dict(claims, Signatures=current)},
                {"time": stamp, "kind": "connector_write", "data": {
                    "request": request, "approval_id": claims["ID"],
                    "result": "read-only" if case == "unapproved" else "verified",
                }},
            ])
        bundle = json.loads(run(
            "collect", "--window", save("records.json", records), "--private-key", private_key,
            "--start", "2025-08-01T00:00:00Z", "--end", "2025-08-03T00:00:00Z",
        ))
        if case == "invalid_window":
            bundle["records"][0]["data"]["EventID"] += "-tampered"
        args = ("compliance", "report", "--bundle", save("bundle.json", bundle), "--queries", queries,
                "--pubkey", public_key, "--approver-keys", approver_keys)
        start = perf_counter()
        output = run(*args)
        elapsed_ms = (perf_counter() - start) * 1000
        assert run(*args) == output
        markdown = run(*args, "--format", "markdown")
        assert run(*args, "--format", "markdown") == markdown
        yield case, json.loads(output), markdown, elapsed_ms
