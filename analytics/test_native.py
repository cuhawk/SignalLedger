import json

import duckdb
import pytest

from analytics.engine import ROOT, export_parquet
from analytics.native import read_events


def test_native_parquet_fields(tmp_path):
    fixtures = ROOT / "analytics" / "testdata" / "wave4"
    events = list(read_events(fixtures / "cloudtrail-benign.json", "cloudtrail"))
    events.extend(read_events(fixtures / "okta-benign.jsonl", "okta"))
    parquet = export_parquet(events, tmp_path / "native")
    with duckdb.connect() as db:
        rows = db.execute("""
            SELECT metadata.uid, class_uid, activity_id, type_uid, time, status_id,
                   metadata.version, actor.user.uid, src_endpoint.ip, unmapped.kind,
                   api.operation
            FROM read_parquet(?)
        """, [parquet]).fetchall()
    by_id = {uid: rest for uid, *rest in rows}
    assert len(by_id) == 10
    assert by_id["aws-role"] == [6003, 1, 600301, 1754051696123, 1, "1.1.0",
                                 "AIDATEST", "192.0.2.14", "assume_role", "AssumeRole"]
    assert by_id["aws-iam-key"][:3] == [6003, 1, 600301]
    assert by_id["aws-console"][:5] == [3002, 1, 300201, 1754051696123, 1]
    assert by_id["aws-console-failed"][4] == 2
    assert by_id["okta-ordinary"] == [3002, 1, 300201, 1754051696123, 1, "1.1.0",
                                      "00utest", "2001:db8::1", "login", None]
    assert by_id["okta-denied-policy"][:5] == [3003, 99, 300399, 1754051696123, 2]


def test_native_rejects_malformed_input_without_publishing(tmp_path):
    source = tmp_path / "feed.jsonl"
    source.write_text(json.dumps({"eventName": "Other"}) + "\n"
                      + json.dumps({"eventName": "AssumeRole", "eventID": "a",
                                    "eventTime": "2025-01-01T00:00:00"}) + "\n")
    snapshot = tmp_path / "native"
    with pytest.raises(ValueError, match=r"feed.jsonl:2: event 1: invalid event timestamp"):
        export_parquet(read_events(source, "cloudtrail"), snapshot)
    assert not snapshot.exists()
