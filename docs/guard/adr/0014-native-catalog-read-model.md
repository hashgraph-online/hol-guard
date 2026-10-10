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
- **Unavailable native.** If the native runtime or capability is unavailable, `/v2/` returns 501 `catalog_read_model_unavailable`. Clients treat that response, or a 404 from an older daemon, as protocol absence and fall back to v1. A busy or timed-out resident returns 503 `catalog_read_transport_failed`, which is retryable and not a fallback signal. Auth errors, 413, 429 and 5xx never trigger fallback.
- **Authentication.** `/v2/extension-controls/` routes pass the same daemon token, session, origin and CORS checks as `/v1/` before any ETag comparison or metadata disclosure.
- **Index contents.** Index summaries carry the fields that list rows, area filters and alias resolution need: identity, publisher, counts, risk and trust classes, `description`, `action_classes`, `aliases`, `ecosystem_ids`, `executables`, `catalog_defaults` and `content_revision`. Permissions, rules, MCP tools and delegated protection stay behind per-extension detail and collection routes.
- **Permission search.** `GET /v2/extension-controls/catalog/permissions?q=&limit=&cursor=` (`guard.daemon.catalog-permission-search.v2`) pages permissions across the whole catalog in index order: extension ID, then source order. Rust lowercases the query and splits it on whitespace. Every term must occur in one of these fields:
  - the permission's `label`, `example_command`, `permission_id`, `description` or `family`
  - the owning extension's `name`, `extension_id` or `executables`

  The match text is built once, with the snapshot. `extension-controls patterns` uses this route rather than reading every extension. It applies its narrower phrase filter on top of the result, so its output matches v1.
- **Unique permissions.** A permission ID that appears twice anywhere in the catalog fails snapshot construction with `catalog_read_model_duplicate_permission`. This keeps search results and per-permission references unambiguous.
- **Codec.** v2 bodies are JSON. A benchmark compared JSON and Protobuf on the same pages.
  - Size: compressed with gzip, the two are within 4% on index pages. On permission pages Protobuf is 21% smaller.
  - Speed: the Python client decodes and validates Protobuf several times more slowly, about 4x on permission pages.
  - Cost: Protobuf would also add a runtime dependency and a second schema to keep in step.

  Protobuf is not used in production. Revisit only with a new measured decision.
- **Separation.** The read model is static catalog metadata. It never reads or changes effective control state, trust classes, managed revisions or hook decisions. `catalog_defaults.enabled` is the packaged default, not effective protection.

## Retired later

The legacy v1 route stays supported and keeps its shape. In-repo callers move to v2 in Stage C. The Python `catalog()` full materialization stays the v1 implementation until v1 has no supported callers. That removal is tracked separately and needs its own deprecation window.

The v1 body is not served from Rust bytes. A wheel without a native runtime must still serve v1, so the Python serializer has to stay. Serving Rust bytes when native is present would add a second v1 serializer, and the two outputs could drift. The v1 size check measures the exact HTML-escaped bytes the daemon writes, so it does not depend on another serializer's output.

Each Python piece on the catalog read path is either a permanent boundary or a temporary bridge:

| Piece | Status | Removal condition |
| --- | --- | --- |
| `native_catalog_read.py` (bounded resident transport) | Permanent while Python owns the daemon HTTP boundary | Removed only if HTTP moves out of Python, under a separate ADR |
| `daemon/catalog_read_v2.py` (auth, raw bounds, status mapping, rollback switch) | Permanent while Python owns the daemon HTTP boundary | Same as above |
| `daemon/catalog_v2_client.py` and `cli/extension_catalog_reads.py` v2 paths (CLI formatting) | Permanent CLI client | None; they format Rust pages and build no catalog state |
| `ExtensionControlApi.catalog()` and `GET /v1/extension-controls/catalog` | Temporary bridge, still supported | Every supported CLI, dashboard and desktop release reads v2; wheels without a native runtime are no longer supported; then a deprecation window of at least one minor release with a `Deprecation` header |
| CLI `_v1_extensions` fallback and dashboard `catalogReadModelFromCatalog`/`localSearch` | Temporary bridge for daemons without v2 and for the rollback switch | Removed together with the v1 route, after the rollback switch has been unused for one release |
| Cloud v1 catalog metadata and handshake | Separate contract, unchanged | Only a negotiated Cloud protocol version can change it |

No bridge may become a second authority. `test_v2_python_boundary_never_reserializes_the_catalog` keeps the v2 modules from building catalog content. `test_v2_read_model_is_reachable_only_from_read_paths` keeps read metadata out of store, authority, policy and Cloud sync code. `test_protocol_absence_is_the_only_fallback_signal` and the dashboard fallback tests keep the v1 bridges limited to protocol absence. Python control-plane functions are not removed to raise the Rust share; each removal needs its condition above.

## Consequences

A wheel without a native runtime still serves v1. `snapshot_id` is bound to the catalog content and the read-model version, not to a process. Restarting the same binary keeps it, so cursors and ETags stay valid. A binary with a different catalog or read-model version changes it. Cursors from the old snapshot then return 409 `catalog_snapshot_expired`, and clients restart the traversal once. The snapshot is immutable for the life of the process, so there is no replacement race; a new catalog arrives only with a new native binary.

Older clients are bounded by their own v1 read limit. Clients released before the catalog limit split read the v1 catalog with a 1,000,000-byte cap. The daemon serves the packaged catalog (136 extensions) as 1,040,518 bytes, because the v1 route keeps its default `json.dumps` separators; the same content is 992,180 bytes compact. Those clients therefore already fail closed with a response-too-large error against a current daemon. They do not truncate it, and compacting the v1 body would leave under 1% headroom, so it is not a compatibility fix. Upgrading the client moves `extension-controls list`, `show` and `patterns` onto bounded v2 pages. Against a daemon without v2, upgraded clients read v1 within the separate daemon response limit.

On a daemon that serves v2, `extension-controls list` returns index summaries (`guard.cli.extension-catalog-list.v2`) rather than full extension objects. `show` still returns the full v1 extension object, rebuilt from detail plus complete collection traversals.

The dashboard reads the same v2 routes. Its first page loads only index pages: 111,428 bytes in two pages for the packaged catalog, against 1,040,518 bytes for v1. One extension's detail and collections load only when its page opens, and pattern search uses `permissions?q=`. Effective controls are always read from `/v1/extension-controls/effective`.

## Rollout and rollback

The v2 read path is on by default. Setting `HOL_GUARD_CATALOG_READ_V2=off` (also `0`, `false` or `disabled`) in the daemon's environment makes every v2 route answer 501 `catalog_read_model_unavailable` without calling the native read model. The CLI and dashboard treat that as protocol absence and read the legacy v1 catalog. Rollback leaves the stage A limits, Cloud v1 metadata, authority records and native enforcement unchanged. It also restores the whole-catalog cost on every load and the older-client limit described above.

- **Diagnostics.** An authenticated `GET /v2/extension-controls/catalog/index` shows which path is active:
  - 200 with `snapshot_id` and `native_catalog_digest`: v2 is served.
  - 501 `catalog_read_model_unavailable`: the switch is off, or the native runtime or its `catalog-read-model-v1` capability is missing.
  - 503 `catalog_read_model_unavailable`: the resident accepted the read but could not build a trusted snapshot. Clients surface this response and do not fall back.
  - 503 `catalog_read_transport_failed`: the resident pool was busy or the read timed out. Retry; clients do not fall back.
  - 503 `catalog_snapshot_mismatch`: the daemon registry and the native catalog differ, so the wheel's daemon and runtime are mismatched. Clients do not fall back.
- **Downgrade.** A daemon from before v2 answers `/v2/` with 404 `not_found`, and upgraded clients read v1. Downgrading the client leaves the daemon unchanged, and the older client keeps reading v1. Cursors and ETags survive a restart of the same binary. After a change to a different catalog, they return 409 or a full 200, and clients restart from the first page.
- **Cloud.** This change adds no Cloud protocol version. Any later changed-record Cloud sync must ship receiver-first: the receiver accepts the new version before any daemon sends it, and v1 stays accepted throughout.
