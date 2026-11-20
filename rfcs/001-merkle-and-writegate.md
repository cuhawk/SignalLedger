# RFC 001 · Evidence windows and conditional connector writes

## Evidence format

A record includes an event time, a kind, and data. The collector signs closed UTC windows with inclusive start and exclusive end. A window must contain at least one evidence record or heartbeat, and empty windows return `FAIL_EMPTY_WINDOW`. Heartbeat producers should report observed collector activity since the last check.

Records are canonicalized with RFC 8785 and hashed as `SHA-256(0x00 || JCS(record))`. Parent nodes use `SHA-256(0x01 || left || right)`. For uneven trees, the left subtree spans the greatest power of two strictly below the subtree size as defined in RFC 6962. The Ed25519 signature covers a JCS statement containing the root, count, bounds, control IDs, and signer-reported signing time. The signing time is an attestation by the signer. Independent timestamping requires a time authority.

The verifier trusts a separately distributed public key. An inclusion proof binds a record to its signed index and window. Complete-window verification recomputes the ordered tree and count. Retain and publish signed roots independently of the collector journal to make collection gaps and unauthorized replacements detectable.

| Evidence | SOC 2 | ISO 27001:2022 |
| --- | --- | --- |
| Connector policy outcomes and access approvals | CC6.1 | A.5.15 |
| Telemetry findings, capture heartbeats and investigation evidence | CC7.2 | A.8.15, A.8.16 |
| Approved state changes, conditional execution and readback | CC8.1 | A.8.15 |

These mappings identify relevant evidence for each control. Auditors evaluate control effectiveness separately.

## Conditional mutation

1. Evaluate the connector/action allowlist and require a single opaque target ID. The gate accepts structured requests with fixed actions. Advisory text, wildcard selectors, and bulk instructions cannot serve as targets or actions.
2. Read the target and emit a dry-run plan. Bind the active flag, provider revision, and policy-relevant details into the JCS/SHA-256 state hash.
3. Verify signatures from two distinct configured Ed25519 keys over identical claims. Claims include the connector, action, target, exact state hash, named approvers, expiry and unique approval ID. Re-read and compare the hash.
4. Atomically reserve the approval ID in the shared replay store and append the authorization to the evidence journal. Mint a single-target credential with a maximum 30-second validity. Keep an approval ID consumed when the remote outcome is uncertain.
5. Apply the exact scoped action conditionally. Revision checking and mutation must be atomic at the service that owns the resource. Changes after the last read therefore produce a revision failure.
6. Read back the target and confirm it is inactive. Record the outcome, including any block, in the evidence journal. A timeout or failed readback requires reconciliation because the provider may have committed the change.

The HTTP adapter expects a trusted service with `GET /{connector}/{action}/{target}` returning a strong ETag and `{"active":true,"details":{}}`. Its `PATCH` route must authenticate an audience-, action-, target- and expiry-bound credential, enforce `If-Match` and `Idempotency-Key`, and return 204 only for a committed mutation. Resources where the upstream API cannot provide atomic conditional behavior remain read-only. Separate gate instances must share the same replay store and stable approval IDs.
