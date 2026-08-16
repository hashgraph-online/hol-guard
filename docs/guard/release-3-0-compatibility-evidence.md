# `release/3.0` 2.1/2.2 compatibility evidence

Status: alpha gate evidence. Audience: compatibility gate reviewers.

This document records historical baseline evidence that the release train preserves the 2.1/2.2 local client contracts required by the execution-assurance program: policy, receipt, runtime-session, protection, and approval payloads, plus the surface-schema/runtime method-list negotiated contract and archived receipt-rollup reconstruction. Each claim cites the authoritative source and the focused test that established it. The evidence was captured from `origin/release/3.1` at `10348fd40fa53ef60d9363bb6c37591b8bb60a61`; PR #1901 migrates the release identity to 3.0. This snapshot is a baseline, not a claim that the cited commit contains the later cutover or the current PR head.

## Verdict summary

| Contract area | 2.2 vs 3.0 | Verdict | Evidence |
| --- | --- | --- | --- |
| Policy payloads | v1 parser present; dispatcher routes by `contractVersion` | Compatible | `test_policy_bundle_parser.py` (58), `test_policy_bundle_trust_regressions.py` (14), `test_policy_bundle_v2.py` (17), `test_policy_bundle_integrity.py` (2) — 129 passed |
| Receipt payloads | `store_receipts.py`, `store_event_receipts.py` byte-identical | Compatible | `test_guard_receipt_persistence.py` — passed |
| Runtime-session payloads | `store_sessions.py` byte-identical | Compatible | covered by store parity |
| Protection payloads | `runtime/effect_contract.py` byte-identical | Compatible | `test_guard_effect_contract.py` — 50 passed |
| Approval payloads | versioned materialization | Compatible | `test_guard_approval_policy_versions.py` — 4 passed |
| Surface schema ↔ runtime methods | negotiate via `initialize_client` | Explicit contract | `runtime/surface_server.py:60-114`, `schemas/surface_server.py:165-175` |
| Receipt-rollup reconstruction | historical backfill proven | Compatible | `test_guard_receipt_persistence.py::test_store_upgrade_rebuilds_historical_warn_rollup_bucket`, `test_guard_storage_maintenance.py` |

## Policy payloads

`release/3.0` retains a dual-parser architecture. `policy_bundle_parser.py` keeps the v1 (2.x) `validated_policy_bundle_payload()` path and adds the v2 (3.0) `validated_policy_bundle_v2_payload()` path. The dispatcher `validate_synced_policy_bundle()` in `policy_bundle_trusted_keys.py:493` routes on `contractVersion`: `guard-policy-bundle.v1` payloads continue to the v1 parser, and `guard-policy-bundle.v2` payloads route to the v2 module. The policy keyring wrapper retains `POLICY_BUNDLE_KEYRING_CONTRACT_VERSION = "guard-policy-keyring.v1"` and validates `contractVersion`/`purpose` before accepting keys, so legacy 2.x keyrings are accepted while 3.0 v2 bundles are verified separately.

The prior concern that the sync path "only routes to v2" was incorrect: the dispatcher explicitly branches on `contractVersion` and preserves the v1 path.

Evidence:

- `policy_bundle_parser.py` — v1 `validated_policy_bundle_payload()` and resource-limit guards.
- `policy_bundle_trusted_keys.py:493` — `validate_synced_policy_bundle()` `contractVersion` dispatch.
- `policy_bundle_trusted_keys.py:20` — `POLICY_BUNDLE_KEYRING_CONTRACT_VERSION = "guard-policy-keyring.v1"`.
- Tests: `tests/test_policy_bundle_parser.py` (58), `tests/test_policy_bundle_trust_regressions.py` (14), `tests/test_policy_bundle_v2.py` (17), `tests/test_policy_bundle_integrity.py` (2) — **129 passed**.

## Receipt payloads

The receipt storage layer is unchanged between 2.2 and 3.0. `store_receipts.py`, `store_event_receipts.py`, `store_receipt_rollups.py`, and `receipts/manager.py` are byte-identical (matching blob SHAs) between `origin/release/2.2` and `origin/release/3.0`. A 2.1/2.2 receipt record is read and written by 3.0 with the same schema and framing.

Evidence:

- Blob parity: `store_receipts.py`, `store_event_receipts.py`, `store_receipt_rollups.py`, `receipts/manager.py` identical across the two refs.
- Tests: `tests/test_guard_receipt_persistence.py` — passed.

## Runtime-session payloads

`store_sessions.py` is byte-identical between 2.2 and 3.0. Runtime-session records created by 2.1/2.2 are read by 3.0 without migration.

Evidence: blob parity for `store_sessions.py`.

## Protection payloads

`runtime/effect_contract.py` is byte-identical between 2.2 and 3.0, including the typed `ProtectionHealth` contract (`runtime/effect_contract.py:295`). The earlier concern that a typed `ProtectionHealth` "replaces arbitrary dicts" in a breaking way is not supported: the contract file did not change between the two releases, so 2.x protection state and 3.0 protection state use the same contract.

Evidence:

- Blob parity for `runtime/effect_contract.py`.
- Tests: `tests/test_guard_effect_contract.py` — **50 passed**.

## Approval payloads

`store_approvals.py` is versioned: legacy and enriched approval records are materialized into the same canonical queue identity (`_QUEUE_IDENTITY_VERSION = "v1"`), and policy-version precedence is exercised so a policy change is the only component that alters evaluation. The 3.0 change removed the legacy browser-label repair helpers and consolidated scanner-evidence/decision-v2 columns, but approval requests deduplicate on the same request identity, so 2.x and 3.0 approval payloads collapse to one record.

Evidence:

- `store_approvals.py` `_QUEUE_IDENTITY_VERSION` and canonical materialization.
- Tests: `tests/test_guard_approval_policy_versions.py` — **4 passed**.

## Surface schema ↔ runtime method-list negotiated contract

The prior blocker ("surface schema method list and runtime method list require an explicit negotiated contract") is resolved by the existing handshake. `initialize_client()` in `runtime/surface_server.py:60` returns both lists in one response: `schema.methods` (advertised surface methods) and `server_capabilities.methods` (the implemented runtime methods from `SERVER_METHODS`). Protocol negotiation uses same-major-version matching (`_negotiate_protocol_version`), and the response carries `protocol_version`, `schema_version`, and the negotiated version. A 2.x client calling `initialize` receives the full implemented-method list and the negotiated protocol version; the three schema-advertised but unimplemented methods (`operation/item/add`, `client/attach`, `client/heartbeat`) are absent from `SERVER_METHODS` and therefore are never routed.

Evidence:

- `runtime/surface_server.py:21-38` — `SERVER_METHODS` (16 implemented methods).
- `runtime/surface_server.py:60-114` — `initialize_client()` returns `schema`, `server_capabilities.methods`, and `negotiated_version`.
- `schemas/surface_server.py:165-175` — advertised method list.
- Both files byte-identical to 2.2.
- Characterization tests `tests/test_guard_release_3_0_compatibility.py::TestSurfaceRuntimeNegotiationContract` pin the handshake contract: both method lists returned together, unimplemented advertised methods never routed, and same-major-version protocol negotiation (accepted and rejected).

## Archived receipt-rollup reconstruction

The blocker requiring migration evidence for archived receipt-rollup reconstruction is resolved by existing proof. `backfill_receipt_rollups()` in `store_receipt_rollups.py` rebuilds rollup state from the `runtime_receipts` table (whose schema is byte-identical to 2.2), and `test_store_upgrade_rebuilds_historical_warn_rollup_bucket` proves that a store upgrade reconstructs the historical rollup bucket from archived receipts. `test_guard_storage_maintenance.py` proves `receipt_rollups_need_backfill`/`backfill_receipt_rollups` reconcile dirty and deleted rollup rows.

Evidence:

- `store_receipt_rollups.py` — `backfill_receipt_rollups()`, byte-identical to 2.2.
- Tests: `tests/test_guard_receipt_persistence.py::test_store_upgrade_rebuilds_historical_warn_rollup_bucket`, `tests/test_guard_storage_maintenance.py` — passed.
- Characterization tests `tests/test_guard_release_3_0_compatibility.py::TestLegacyReceiptRollupReconstruction` simulate a 2.x-era store (migrations 10 and 16 applied, stale rollup bucket) and prove `backfill_receipt_rollups` reconstructs archived rollups idempotently.

## Harness coverage (degraded/unsupported)

Harnesses that cannot enforce authenticated local decisions remain degraded or unsupported for mandatory assurance. This is an accepted alpha limitation, not a resolved blocker, and is tracked by the harness matrix work in later waves.

## Reproduce

```bash
git checkout 10348fd40fa53ef60d9363bb6c37591b8bb60a61
uv run --no-sync pytest -q tests/test_policy_bundle_parser.py tests/test_policy_bundle_trust_regressions.py tests/test_policy_bundle_v2.py tests/test_policy_bundle_integrity.py
uv run --no-sync pytest -q tests/test_guard_receipt_persistence.py tests/test_guard_storage_maintenance.py
uv run --no-sync pytest -q tests/test_guard_effect_contract.py tests/test_guard_approval_policy_versions.py
uv run --no-sync pytest -q tests/test_guard_release_3_0_compatibility.py
```

No release, publication, deployment, or policy activation is authorized by this document.
