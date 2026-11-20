# CODEX_SPEC: SignalLedger — Go/DuckDB SIEM-less OCSF Detection, TOCTOU-Safe Write-Gate & RFC 8785/6962 Merkle Evidence Engine

Build a deeply engineered Go + Python/DuckDB security telemetry, connector governance, and cryptographic audit evidence system (real hashing, real DuckDB SQL execution over Parquet, real tamper/red-team test suites, NO fake outputs).

## Required Architecture & Non-Trivial Invariants
1. **Go Log Collector & OCSF Normalizer (`internal/ingest/`):**
   - Connector interfaces + realistic Entra ID (`Microsoft Graph signIn/directoryAudit`) and Google Workspace (`Admin Reports` + `Calendar/Notion OAuth & share events`) parsers normalizing into canonical **OCSF** (`Authentication`, `API Activity`, `Account Change`) structs.
   - Cursor pagination state, HTTP `429 Retry-After` jittered exponential backoff (unit-tested with mock HTTP server simulating 429 + partial pages + schema drift), **event-time watermarks** for out-of-order late arrival (`<=24h` skew), and idempotent `(vendor_event_id, payload_sha256)` deduplication.
   - Single-writer Parquet/JSONL batch flusher respecting DuckDB concurrency rules.
2. **DuckDB Over Partitioned Parquet + Detection-as-Code (`internal/detect/` + `rules/*.yaml` + Python analytics):**
   - Compiles declarative YAML detection rules into parameterized DuckDB SQL queries over Parquet partitions (working BOTH via `duckdb` Python CLI/library cleanly verified in CI and structured Go SQL runner):
     1. Password spray (many users, low attempts per account within sliding window),
     2. MFA fatigue burst (repeated denied MFA push followed by accept from new IP/ASN),
     3. Impossible travel with curated corporate VPN/ASN allowlist,
     4. Illicit OAuth / Calendar / Notion connector scope escalation (`Calendar.ReadWrite` / bulk export),
     5. Token replay across distinct ASN/device fingerprint.
   - Synthetic multi-day benign baseline + attack trace generator (`OTRF` / `Atomic Red Team`-modeled event shapes) + evasion cases (slow spray, mutated event IDs replay) measuring real **precision, recall, latency, FP/1k events** saved to `benchmarks/RESULTS.md`.
3. **TOCTOU-Safe Connector Write-Gate (`internal/writegate/`):**
   - Default mode is strictly **READ-ONLY**.
   - Every state mutation (`revoke_oauth_grant`, `disable_user`, `revoke_calendar_acl`, `quarantine_notion_share`) passes a strict 6-step gate:
     1. Policy rule evaluation (denies wildcard targets / bulk `"disable all admins"` hostile LLM suggestions),
     2. Pre-mutation `dry-run` state snapshot & diff computation (`state_hash`),
     3. **Target-State-Hash-Bound Two-Person Approval:** approval signature binds `(action, target_id, pre_state_hash, approver1, approver2, expiry)` — if target state mutates before execution (**TOCTOU race**), gate aborts cleanly!
     4. Short-lived minimally scoped execution token + single-use idempotency key (replay blocked),
     5. Connector execution,
     6. Post-action readback verification.
   - Logs every blocked hostile/replayed/TOCTOU attempt to the tamper-evident ledger.
4. **RFC 8785 JCS + RFC 6962 Ed25519 Merkle Evidence Collector (`internal/merkle/` + `cmd/signalledger verify`):**
   - Canonicalizes each evidence record using **RFC 8785 JSON Canonicalization Scheme (JCS)** before SHA-256 hashing.
   - Domain-separated Merkle tree per **RFC 6962**: leaf hash `SHA256(0x00 || canonical_bytes)`, internal node `SHA256(0x01 || left || right)` (prevents second-preimage attacks!).
   - Ed25519 root signature + timestamp attestation metadata + inclusion proof generation & offline CLI verifier (`signalledger verify --root ... --proof ... --leaf ... --pubkey ...`).
   - **Liveness invariant:** Collector refuses to mark a compliance window `PASS` if 0 records/heartbeats were collected (`FAIL_EMPTY_WINDOW` prevents silent audit blindness!).
   - Maps controls cleanly to **SOC 2 (CC6.1, CC7.2, CC8.1)** and **ISO 27001:2022 (A.5.15, A.8.15, A.8.16)**.
5. **Mandatory Adversarial Tamper & CI Suites (`go test -race ./...` + `pytest`):**
   - Tamper suite tests: flip 1 byte, reorder 2 leaves, delete a leaf, splice leaf from adjacent window, forge signature, empty window -> **100% rejected**.
   - Write-gate red-team suite: replay approval, escalate scope, TOCTOU target state drift, hostile `"disable all admins"` LLM prompt -> **100% blocked**.
   - `.github/workflows/ci.yml`: Go `-race` tests + Python DuckDB detection/evasion tests + benchmark generation (`benchmarks/RESULTS.md`).
   - `rfcs/001-merkle-and-writegate.md` + `README.md` + **CRITICAL: `git rm CODEX_SPEC.md` before finishing!**
