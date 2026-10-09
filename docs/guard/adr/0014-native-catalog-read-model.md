# ADR 0014: Native catalog read model and v2 transport

Status: accepted for implementation.

## Context

The legacy `GET /v1/extension-controls/catalog` returns every extension, permission and rule in one body. That body is about 1.04 MB for the built-in catalog today and can reach the 8,000,000-byte local budget. Dashboard and CLI callers need to page through the catalog, view one extension at a time and revalidate cheaply. The Python daemon is the current HTTP and authentication boundary. Native Rust already owns command compilation, the embedded catalog bound to the program digest, and the resident IPC described in [ADR 0008](0008-native-resident-protocol-and-admission.md).

## Decision

- **Ownership.** The new catalog read model lives in Rust: `guard-command` module `catalog_read_model`. It owns these pieces:
  - immutable snapshot construction
  - stable ordering (index by extension ID; collections in catalog source order, which v1 consumers already see) and filtering
  - byte-aware pagination, with the envelope counted in HTML-safe escaped bytes
  - snapshot-bound cursor encoding and verification
  - per-representation ETags and `If-None-Match` evaluation
  - DTO serialization

  Python adds no catalog index, cache, cursor or serializer.
- **Trusted bytes.** The snapshot is built once per process from the catalog that `guard-command` embeds at build time. That is the same artifact `packaged_command_catalog()` binds to the native program digests. Construction recomputes the canonical SHA-256 of the extension array and requires it to equal the envelope `catalog_digest`. It also requires `packaged_command_catalog()` to succeed. Any mismatch fails closed with `catalog_read_model_unavailable`. The managed resident starts this build on a background thread at startup, so the first `catalog_read` does not pay for it; a construction failure surfaces on that read.
- **Transport.** The resident op `catalog_read` is versioned and read-only. It is advertised as resident capability `catalog-read-model-v1` on the existing resident protocol, and the Python daemon reaches it through the pooled resident client stream. There is no per-request process spawn and no new listener or HTTP daemon.
  - **Request.** The daemon sends the raw route suffix, the raw query string and the `If-None-Match` header value, all size-bounded. It also sends the `catalog_digest` of the registry it serves. Rust parses all of these; Python does not interpret them.
  - **Digest mismatch.** If the digests differ, Rust returns `catalog_snapshot_mismatch`, so a daemon never serves pages from a different catalog than its legacy route.
- **Status crossing.** Rust returns `guard-catalog-read-result.v1`, which holds `outcome` (`ok`, `not_modified` or `error`), `http_status`, `etag` and `body`. The body is a JSON text string that is already HTML-safe. Python writes `body` verbatim, sends a bodyless 304 for `not_modified`, and maps `error` to its HTTP status with the Rust error code.
- **Unavailable native.** If the native runtime or capability is unavailable, `/v2/` returns 501 `catalog_read_model_unavailable`. Clients treat that response, or a 404 from an older daemon, as protocol absence and fall back to v1. Auth errors, 413, 429 and 5xx never trigger fallback.
- **Authentication.** `/v2/extension-controls/` routes pass the same daemon token, session, origin and CORS checks as `/v1/` before any ETag comparison or metadata disclosure.
- **Separation.** The read model is static catalog metadata. It never reads or changes effective control state, trust classes, managed revisions or hook decisions. `catalog_defaults.enabled` is the packaged default, not effective protection.

## Retired later

The legacy v1 route stays supported and keeps its shape. In-repo callers move to v2 in Stage C. The Python `catalog()` full materialization stays the v1 implementation until v1 has no supported callers. That removal is tracked separately and needs its own deprecation window.

## Consequences

A wheel without a native runtime still serves v1. A resident restart, or a binary with a different catalog, changes `snapshot_id`. Cursors from the old snapshot then return 409 `catalog_snapshot_expired`, and clients restart the traversal once. The snapshot is immutable for the life of the process, so there is no replacement race; a new catalog arrives only with a new native binary.
