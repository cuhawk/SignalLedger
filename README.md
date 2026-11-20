# SignalLedger

SignalLedger collects SaaS audit telemetry into OCSF events, runs detections over date-partitioned Parquet, gates narrowly scoped connector mutations, and signs evidence windows for offline verification.

## Build and test

Use Go 1.25, a C compiler, and Python 3.12. Install the Python dependencies with `python -m pip install -r analytics/requirements.txt`. The Go DuckDB driver supports its default bundled build or the DuckDB 1.5.4 shared library. CI uses the shared library. On Linux, unpack the release into an absolute directory and set the following variables.

```sh
export GOFLAGS=-tags=duckdb_use_lib
export CGO_LDFLAGS="-L$DUCKDB_LIB_DIR"
export LD_LIBRARY_PATH="$DUCKDB_LIB_DIR"
go build -o /tmp/signalledger ./cmd/signalledger
go test -race -v ./...
SIGNALLEDGER_BIN=/tmp/signalledger python -m pytest -v analytics
```

To regenerate [measured results](benchmarks/RESULTS.md), run `go test -race -v -count=1 -json ./... > /tmp/signalledger-go.jsonl`, then `python -m analytics.benchmark --go-report /tmp/signalledger-go.jsonl --cli /tmp/signalledger`.

On the synthetic benchmark, distributed slow-spray recall rose from 0/3 with the single-source rule to 3/3 with the distributed rule. Median detection latency was 70 minutes of event time. DuckDB evaluation took 77.1 ms across 1,539 events. The benign baseline produced 0 false positives across 1,452 events. The Merkle suite rejected 6/6 signed-window tamper cases and 10/10 consistency tamper, truncation, and rollback cases. The consistency prefix matrix and RFC 6962 proof-vector test passed.

The signed auditor fixture passed 8 of 27 control checks, verified 4 Merkle records and 1 oversight receipt, and took 94.9 ms end to end. Missing, unapproved, and invalid-signature receipt fixtures each passed 3 of 27 checks with 0 verified oversight receipts. The tampered window passed 0 of 27 checks with 0 verified Merkle records.

On the native synthetic fixtures, each new rule detected its one labeled event with 0 ms of event-time latency. DuckDB evaluated the 12-event mixed fixture in 38.2 ms. The 10-event benign baseline produced 0 false positives. The CLI passed both fixtures and rejected malformed YAML and an incorrect expected finding set.

## Collect and detect

Provide a read-scoped bearer in `SIGNALLEDGER_AUDIT_TOKEN` and keep a separate journal per tenant and feed. Run `ingest` on a schedule. `--since` sets the earliest timestamp eligible for collection. The collector resumes a persisted page cursor and overlaps completed scans by up to 24 hours. Each immutable JSONL batch stores accepted events, the next cursor, and counts for schema rejects, duplicates and events outside the scan window.

| Feed | Endpoint and event shape |
| --- | --- |
| `entra-signin` | Microsoft Graph `/v1.0/auditLogs/signIns` |
| `entra-audit` | Microsoft Graph `/v1.0/auditLogs/directoryAudits` |
| `workspace` | Admin Reports `/admin/reports/v1/activity/users/all/applications/{login,token,admin}`, one journal per application |
| `calendar` | Admin Reports Calendar application, with ACL change events. Connector OAuth grants are collected from the token application. Public ACL changes are flagged when the audit payload identifies a public or default audience |
| `notion` | A trusted Notion audit export relay exposing cursor-paginated `results` with `id`, `timestamp`, `action`, `actor.id`, and optional `details.scopes`, `details.visibility`, and `details.public` |

```sh
/tmp/signalledger ingest --vendor entra-signin \
  --url https://graph.microsoft.com/v1.0/auditLogs/signIns \
  --journal data/entra-signin --since 2025-01-01T00:00:00Z

python -m analytics.engine export data/entra-signin --output data/snapshot-001
python -m analytics.engine compile 'data/snapshot-001/day=*/*.parquet' > /tmp/queries.json
/tmp/signalledger detect --queries /tmp/queries.json
python -m analytics.engine run 'data/snapshot-001/day=*/*.parquet'
```

Add `--journal` once per additional feed directory to include multiple feeds from the same tenant. The Parquet exporter publishes a new snapshot directory atomically. The partition rows retain the normalized OCSF record and expose typed detection fields. The rule compiler supports the selection and correlation forms used in `rules/`. It binds Parquet paths, selection values, thresholds, patterns and allowlists as SQL parameters. Treat compiled SQL bundles as trusted deployment artifacts. Geo, ASN, device and token correlations require corresponding source fields or upstream enrichment. Review the sample corporate egress allowlist before use. The synthetic suite covers public and private shares, reissued event IDs for the same token observation, and distributed slow spray.

## Import CloudTrail and Okta exports

Run these commands from the repository root with the Python analytics dependencies installed. Native imports accept a JSON event object, a JSON array, or line-delimited JSON with a `.jsonl` or `.ndjson` extension. CloudTrail JSON also supports the `Records` envelope. The exporter skips unsupported event names and reports malformed supported records with their input location.

```sh
python -m analytics.engine export-native cloudtrail.json --vendor cloudtrail --output data/aws-001
python -m analytics.engine export-native okta.jsonl --vendor okta --output data/okta-001
python -m analytics.engine run 'data/aws-001/day=*/*.parquet'
```

CloudTrail `AssumeRole` and `CreateAccessKey` map to OCSF 1.1 API Activity. CloudTrail `ConsoleLogin` and Okta `user.session.start` map to Authentication. Okta `policy.evaluate_sign_on` maps to Authorize Session. The new rules flag successful root access key creation in CloudTrail and successful Okta sessions whose source is marked as a proxy in the System Log.

## Validate rules and fixtures

```sh
/tmp/signalledger rule check
/tmp/signalledger rule check --fixture analytics/testdata/wave4/mixed.fixture.json
/tmp/signalledger rule check --fixture analytics/testdata/wave4/benign.fixture.json
```

Pass `--rules DIR` to validate a custom rule directory. The fixture JSON lists native inputs by `path` and `vendor`, plus exact expected `[rule_id, event_id, time_ms]` findings. Relative input paths resolve from the fixture directory. Invalid rules and missing or unexpected findings return a nonzero exit code. The command uses the Python analytics environment through `python3` on PATH or the interpreter set in `SIGNALLEDGER_PYTHON`.

## Gate writes and verify evidence

Applications can wire the Go write-gate to a durable `DirectoryReplay` store and `merkle.Journal`. The gate is read-only unless explicitly enabled. A mutation connector must offer provider-side conditional writes against a strong revision. The included `ConditionalHTTP` adapter uses a trusted conditional mutation service with a caller-supplied scoped credential issuer. Each provider remains read-only until an endpoint satisfies that contract. See the [RFC](rfcs/001-merkle-and-writegate.md).

Collect an evidence window from the journal or a JSON array. The signing key file holds a JSON base64-encoded Ed25519 private key. Store it separately from the exported artifacts.

```sh
/tmp/signalledger collect --journal data/evidence --private-key signing-key.json \
  --start 2025-01-01T00:00:00Z --end 2025-01-02T00:00:00Z > bundle.json
jq '.root' bundle.json > root.json
jq '.proofs[0]' bundle.json > proof.json
jq '.records[0]' bundle.json > leaf.json
/tmp/signalledger verify --root root.json --proof proof.json --leaf leaf.json \
  --pubkey trusted-public-key.json
```

For complete-window verification, pass `--window` with the extracted `.records` array in place of `--proof` and `--leaf`. Distribute the public key independently of the evidence bundle. A verification failure returns exit code 1. An empty window yields `FAIL_EMPTY_WINDOW`.
